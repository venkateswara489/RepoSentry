import os
import tempfile
os.environ['DATA_DIR']=tempfile.mkdtemp()
os.environ['DEMO_MODE']='true'
import base64
import json
import time
import pytest
from fastapi.testclient import TestClient
import app as module
from scanner import analyze

@pytest.fixture
def client():
    with TestClient(module.app) as c: yield c

def login(c):
    return {'x-csrf-token':c.get('/api/session').json()['csrf']}

def test_auth_csrf(client):
    assert client.get('/api/scans').status_code==401
    login(client)
    assert client.post('/api/scans',json={'repo':'o/r'}).status_code==403

def test_demo_isolation(client):
    headers=login(client)
    r=client.post('/api/scans',json={'repo':'owner/repo'},headers=headers)
    assert r.status_code==200
    sid=r.json()['id']
    for _ in range(100):
        r=client.get('/api/scans/'+sid).json()
        if r['status']=='completed': break
        time.sleep(.01)
    assert r['status']=='completed'
    assert r['data']['demo']
    assert any(f['replacement'] for f in r['data']['findings'])
    assert client.post('/api/scans/'+sid+'/pull-request',json={'findings':['x']},headers=headers).status_code==404
    with TestClient(module.app) as other:
        login(other)
        assert other.get('/api/scans/'+sid).status_code==404
    assert client.get('/api/me').status_code==404

@pytest.mark.parametrize('value',['https://evil.com/o/r','https://github.com/o/r?x=1','o/..','o/r/../../foo','http://github.com/o/r'])
def test_reject_url(value):
    with pytest.raises(Exception): module.parse_repo(value)

def test_repo():
    assert module.parse_repo('https://github.com/owner/repo.git')=='owner/repo'

def test_redaction():
    value='fake-secret-value-12345'
    findings=analyze({'a.py':f'API_KEY="{value}"\nrequests.get(url, verify=False)\ntry:\n    f()\nexcept Exception:\n    pass\ndef unfinished():\n    pass\n'})
    assert value not in str(findings)
    assert {'secret','tls-verification','swallowed-exception','empty-function'}<={f['rule'] for f in findings}
    assert next(f for f in findings if f['rule']=='tls-verification')['replacement']=='requests.get(url, verify=True)'

def test_clean(): assert analyze({'clean.py':'def add(a,b):\n    return a+b\n'})==[]

def test_oauth_removed(client):
    assert client.get('/auth/callback').status_code==404
    assert client.get('/auth/github').status_code==404
    assert client.get('/auth/demo').status_code==404

def test_headers(client):
    r=client.get('/')
    assert r.status_code==200
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']

def test_live_public_scan_without_credentials(client,monkeypatch):
    headers=login(client)
    calls=[]
    def github(path):
        calls.append(path)
        if '/commits/' in path: return {'sha':'a'*40}
        return {'private':False,'default_branch':'main'}
    monkeypatch.setattr(module,'gh',github)
    monkeypatch.setattr(module,'download_files',lambda repo,sha:({'a.py':'eval(value)'},0))
    monkeypatch.setattr(module,'check_dependencies',lambda files:([],'No dependency pins.'))
    monkeypatch.setattr(module,'DEMO',False)
    sid=client.post('/api/scans',json={'repo':'owner/repo'},headers=headers).json()['id']
    for _ in range(100):
        result=client.get('/api/scans/'+sid).json()
        if result['status'] in ('completed','failed'): break
        time.sleep(.01)
    assert result['status']=='completed'
    assert result['data']['demo'] is False
    assert calls==['/repos/owner/repo','/repos/owner/repo/commits/main']

def test_session_cookie(client):
    r=client.get('/api/session')
    assert 'HttpOnly' in r.headers['set-cookie']
    assert client.get('/api/session').json()==r.json()
    assert client.get('/api/config').json()['publicOnly'] is True

def test_private_repository_rejected(client,monkeypatch):
    headers=login(client)
    monkeypatch.setattr(module,'DEMO',False)
    monkeypatch.setattr(module,'gh',lambda path:{'private':True})
    sid=client.post('/api/scans',json={'repo':'owner/private'},headers=headers).json()['id']
    for _ in range(100):
        result=client.get('/api/scans/'+sid).json()
        if result['status']=='failed': break
        time.sleep(.01)
    assert result['status']=='failed'
    assert 'Only public' in result['data']['error']

def test_dependency_normalization(monkeypatch):
    import dependencies
    class Response:
        def raise_for_status(self): pass
        def json(self): return {'results':[{'vulns':[{'id':'TEST-2026-001'}]}]}
    monkeypatch.setattr(dependencies.httpx.Client,'post',lambda *a,**k:Response())
    findings,status=dependencies.check({'requirements.txt':'example==1.0.0\n'})
    assert findings[0]['confidence']=='advisory-match'
    assert findings[0]['replacement'] is None
    assert '1 pinned' in status

@pytest.mark.parametrize('status,headers,body,expected',[
    (403,{'x-ratelimit-remaining':'0','x-ratelimit-reset':'2000000000'},{'message':'API rate limit exceeded'},'Retry in about'),
    (403,{}, {'message':'Resource not accessible by integration'},'not a confirmed rate-limit'),
    (429,{'retry-after':'120'}, {},'2 minute(s)'),
    (401,{}, {},'invalid or expired'),
])
def test_github_errors(monkeypatch,status,headers,body,expected):
    import httpx
    monkeypatch.setattr(module,'PUBLIC_GITHUB_TOKEN','')
    transport=httpx.MockTransport(lambda request:httpx.Response(status,headers=headers,json=body))
    real_client=httpx.Client
    monkeypatch.setattr(module.httpx,'Client',lambda **kw:real_client(transport=transport,**kw))
    with pytest.raises(RuntimeError,match=__import__('re').escape(expected)):
        module.gh('/repos/owner/repo')

def test_server_token_is_only_in_api_header(client,monkeypatch):
    import httpx
    token='fake-test-server-token'
    monkeypatch.setattr(module,'PUBLIC_GITHUB_TOKEN',token)
    def respond(request):
        assert request.url.host=='api.github.com'
        assert request.headers['authorization']=='Bearer '+token
        return httpx.Response(200,json={'private':False})
    real_client=httpx.Client
    transport=httpx.MockTransport(respond)
    monkeypatch.setattr(module.httpx,'Client',lambda **kw:real_client(transport=transport,**kw))
    assert module.gh('/repos/owner/repo')=={'private':False}
    assert token not in client.get('/api/config').text
