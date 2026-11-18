import json
import httpx
import explanations as ai
from tests.test_app import client,login
import app as module
import time

FINDING=dict(id='one',rule='debug-enabled',title='Debug enabled',severity='medium',path='app.py',line=1,evidence='app.run(debug=True)',advice='Disable debug in production.')
PAYLOAD=dict(issue='Debug is enabled.',impact='May expose internals in production.',suggested_fix='Disable debug for deployment.',verification='Run deployment smoke tests.')

def scan_fixture(client):
    headers=login(client)
    sid=client.post('/api/scans',json={'repo':'sample/repo','sample':True},headers=headers).json()['id']
    for _ in range(100):
        report=client.get('/api/scans/'+sid).json()
        if report['status']=='completed': break
        time.sleep(.01)
    return headers,sid,report['data']['findings'][0]['id']

def test_missing_key_uses_fallback(monkeypatch):
    monkeypatch.delenv('GROQ_API_KEY',raising=False)
    assert ai.generate(FINDING)['status']=='fallback'

def test_redaction_and_prompt_boundary(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','fake-server-key')
    secret='this-is-a-test-credential-123'
    finding=dict(FINDING,evidence=f'password="{secret}"')
    def respond(request):
        assert request.url.host=='api.groq.com'
        assert request.headers['authorization']=='Bearer fake-server-key'
        content=request.content.decode()
        assert secret not in content
        assert 'fake-server-key' not in content
        body=json.loads(content)
        assert 'untrusted evidence' in body['messages'][0]['content']
        return httpx.Response(200,json={'choices':[{'message':{'content':json.dumps(PAYLOAD)}}]})
    real=httpx.Client
    monkeypatch.setattr(ai.httpx,'Client',lambda **kw:real(transport=httpx.MockTransport(respond),**kw))
    result=ai.generate(finding)
    assert result['status']=='generated'
    assert result['explanation']==PAYLOAD
    assert finding['severity']=='medium'

def test_invalid_output_falls_back(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','fake')
    real=httpx.Client
    monkeypatch.setattr(ai.httpx,'Client',lambda **kw:real(transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'choices':[{'message':{'content':'{"issue":"missing fields"}'}}]})),**kw))
    assert ai.generate(FINDING)['status']=='fallback'

def test_api_cache_csrf_and_isolation(client,monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','fake')
    calls=[]
    def generate(f):
        calls.append(f['id'])
        return dict(status='generated',provider='Groq',explanation=PAYLOAD,message='Review suggestions.')
    monkeypatch.setattr(ai,'generate',generate)
    headers,sid,fid=scan_fixture(client)
    path=f'/api/scans/{sid}/findings/{fid}/explain'
    assert client.post(path).status_code==403
    first=client.post(path,headers=headers)
    assert first.status_code==200 and first.json()['cached'] is False
    assert client.post(path,headers=headers).json()['cached'] is True
    assert len(calls)==1
    assert client.post(f'/api/scans/{sid}/findings/missing/explain',headers=headers).status_code==404
    from fastapi.testclient import TestClient
    with TestClient(module.app) as other:
        other_headers=login(other)
        assert other.post(path,headers=other_headers).status_code==404

def test_quota_blocks_remote_call(client,monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','fake')
    headers,sid,fid=scan_fixture(client)
    with module.db() as c:
        owner=c.execute('SELECT owner FROM public_scans WHERE id=?',(sid,)).fetchone()[0]
        c.executemany('INSERT INTO ai_calls VALUES(?,?)',[(owner,time.time())]*20)
    monkeypatch.setattr(ai,'generate',lambda f:(_ for _ in ()).throw(AssertionError('No API call allowed')))
    assert client.post(f'/api/scans/{sid}/findings/{fid}/explain',headers=headers).status_code==429

def test_model_failure_has_actionable_message(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','fake')
    real=httpx.Client
    monkeypatch.setattr(ai.httpx,'Client',lambda **kw:real(transport=httpx.MockTransport(lambda r:httpx.Response(400,json={'error':{'message':'private upstream detail'}})),**kw))
    result=ai.generate(FINDING)
    assert 'GROQ_MODEL' in result['message']
    assert 'HTTP 400' in result['message']
    assert 'private upstream detail' not in str(result)

def test_frontend_is_not_cached(client):
    for path in ('/','/static/app.js','/static/style.css'):
        assert client.get(path).headers['cache-control']=='no-store'
    assert '?v=groq-2' in client.get('/').text
