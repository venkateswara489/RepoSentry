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
    c.get('/auth/demo')
    return {'x-csrf-token':c.get('/api/me').json()['csrf']}

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
    assert client.post('/api/scans/'+sid+'/pull-request',json={'findings':['x']},headers=headers).status_code==400
    with TestClient(module.app) as other:
        login(other)
        assert other.get('/api/scans/'+sid).status_code==404
    assert client.post('/api/logout',headers=headers).status_code==200
    assert client.get('/api/me').status_code==401

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

def test_oauth_state(client): assert client.get('/auth/callback?state=bad&code=fake').status_code==400

def test_headers(client):
    r=client.get('/')
    assert r.status_code==200
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']

def test_pr_selected_pinned_and_mode_preserved(client,monkeypatch):
    headers=login(client)
    with module.db() as c:
        c.execute('UPDATE sessions SET user=?',(json.dumps(dict(login='tester',id='42',demo=False)),))
        c.execute('INSERT INTO scans VALUES(?,?,?,?,?,?)',('live','github:42','owner/repo','completed',json.dumps(dict(commit='a'*40,branch='main',demo=False,findings=[dict(id='fix1',path='app.py',line=1,replacement='verify=True')])),time.time()))
    calls=[]
    def gh(token,method,path,**kwargs):
        calls.append((method,path,kwargs))
        if '/contents/' in path: return {'content':base64.b64encode(b'verify=False\n').decode()}
        if method=='GET' and '/git/commits/' in path: return {'tree':{'sha':'old-tree'}}
        if method=='GET' and '/git/trees/' in path: return {'tree':[{'path':'app.py','mode':'100755'}]}
        if path.endswith('/git/blobs'): assert kwargs['json']['content']=='verify=True\n'; return {'sha':'blob'}
        if path.endswith('/git/trees'): assert kwargs['json']['tree'][0]['mode']=='100755'; return {'sha':'tree'}
        if path.endswith('/git/commits'): return {'sha':'commit'}
        if path.endswith('/pulls'): assert kwargs['json']['draft']; return {'html_url':'https://github.com/owner/repo/pull/1'}
        return {}
    monkeypatch.setattr(module,'gh',gh)
    r=client.post('/api/scans/live/pull-request',json={'findings':['fix1']},headers=headers)
    assert r.status_code==200
    assert r.json()['url'].endswith('/pull/1')
    assert calls[0][1].endswith('?ref='+'a'*40)
    assert not any('/merges' in path for _,path,_ in calls)

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
