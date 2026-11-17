import base64
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, quote
import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import FileResponse,JSONResponse,RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from scanner import analyze,SECRET,EXTENSIONS
from dependencies import check as check_dependencies

ROOT=Path(__file__).parent
DATA=Path(os.getenv('DATA_DIR',str(ROOT/'work')))
DATA.mkdir(parents=True,exist_ok=True)
KEY=os.getenv('ENCRYPTION_KEY')
if not KEY:
    keyfile=DATA/'encryption.key'
    if not keyfile.exists():
        keyfile.write_bytes(Fernet.generate_key()); keyfile.chmod(0o600)
    KEY=keyfile.read_bytes()
CIPHER=Fernet(KEY)
BASE=os.getenv('BASE_URL','http://localhost:8000').rstrip('/')
CLIENT=os.getenv('GITHUB_CLIENT_ID','')
CLIENT_SECRET=os.getenv('GITHUB_CLIENT_SECRET','')
DEMO=os.getenv('DEMO_MODE','false').lower()=='true'
POOL=ThreadPoolExecutor(max_workers=2)
app=FastAPI(title='RepoSentry',docs_url='/api/docs')

@contextmanager
def db():
    c=sqlite3.connect(DATA/'reposentry.db',timeout=20); c.row_factory=sqlite3.Row
    try: yield c; c.commit()
    finally: c.close()

with db() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user TEXT,token TEXT,csrf TEXT,expires REAL);
CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,expires REAL);
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,owner TEXT,repo TEXT,status TEXT,data TEXT,created REAL);
UPDATE scans SET status='failed' WHERE status IN ('queued','downloading','scanning');''')

@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' https://avatars.githubusercontent.com; frame-ancestors 'none'; base-uri 'none'"
    if request.url.path.startswith('/api'): response.headers['Cache-Control']='no-store'
    return response

def session(request,write=False):
    sid=request.cookies.get('session','')
    with db() as c: row=c.execute('SELECT * FROM sessions WHERE id=? AND expires>?',(hashlib.sha256(sid.encode()).hexdigest(),time.time())).fetchone()
    if not row: raise HTTPException(401,'Please sign in first.')
    if write and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']): raise HTTPException(403,'Invalid request token. Refresh and retry.')
    result=dict(row); user=json.loads(result['user'])
    result['owner']='demo:'+result['id'] if user.get('demo') else 'github:'+user['id']
    return result

def create_session(user,token):
    sid,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    with db() as c: c.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(hashlib.sha256(sid.encode()).hexdigest(),json.dumps(user),CIPHER.encrypt(token.encode()).decode(),csrf,time.time()+28800))
    response=RedirectResponse('/',status_code=303)
    response.set_cookie('session',sid,httponly=True,secure=BASE.startswith('https:'),samesite='lax',max_age=28800)
    return response

def gh(token,method,path,**kwargs):
    with httpx.Client(timeout=30,follow_redirects=False) as client:
        r=client.request(method,'https://api.github.com'+path,headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},**kwargs)
    if r.status_code>=400: raise RuntimeError(f'GitHub returned {r.status_code}. Check access and API limits. A failed write can leave a branch.')
    return r.json() if r.content else {}

@app.get('/api/config')
def config(): return {'githubConfigured':bool(CLIENT and CLIENT_SECRET),'demoEnabled':DEMO}

@app.get('/auth/github')
def login():
    if not CLIENT or not CLIENT_SECRET: raise HTTPException(503,'Configure GitHub OAuth credentials first.')
    state=secrets.token_urlsafe(32)
    with db() as c:
        c.execute('DELETE FROM oauth WHERE expires<?',(time.time(),))
        c.execute('INSERT INTO oauth VALUES(?,?)',(state,time.time()+600))
    response=RedirectResponse('https://github.com/login/oauth/authorize?'+urlencode(dict(client_id=CLIENT,redirect_uri=BASE+'/auth/callback',scope='repo read:user',state=state)))
    response.set_cookie('oauth_state',state,httponly=True,secure=BASE.startswith('https:'),samesite='lax',max_age=600)
    return response

@app.get('/auth/callback')
def callback(request:Request,code:str='',state:str=''):
    if not state or not secrets.compare_digest(state,request.cookies.get('oauth_state','')): raise HTTPException(400,'OAuth state mismatch.')
    with db() as c:
        valid=c.execute('SELECT state FROM oauth WHERE state=? AND expires>?',(state,time.time())).fetchone()
        c.execute('DELETE FROM oauth WHERE state=?',(state,))
    if not valid: raise HTTPException(400,'OAuth request expired.')
    with httpx.Client(timeout=30) as client:
        result=client.post('https://github.com/login/oauth/access_token',headers={'Accept':'application/json'},json=dict(client_id=CLIENT,client_secret=CLIENT_SECRET,code=code,redirect_uri=BASE+'/auth/callback')).json()
    token=result.get('access_token')
    if not token: raise HTTPException(400,'GitHub authorization failed.')
    user=gh(token,'GET','/user')
    response=create_session(dict(login=user['login'],id=str(user['id']),avatar_url=user['avatar_url'],demo=False),token)
    response.delete_cookie('oauth_state'); return response

@app.get('/auth/demo')
def demo():
    if not DEMO: raise HTTPException(404)
    return create_session(dict(login='demo-explorer',demo=True),'')

@app.get('/api/me')
def me(request:Request):
    s=session(request); return dict(user=json.loads(s['user']),csrf=s['csrf'])

@app.post('/api/logout')
def logout(request:Request):
    s=session(request,True)
    with db() as c: c.execute('DELETE FROM sessions WHERE id=?',(s['id'],))
    response=JSONResponse({'ok':True}); response.delete_cookie('session'); return response

@app.get('/api/repos')
def repos(request:Request):
    s=session(request)
    if json.loads(s['user']).get('demo'): return []
    rows=gh(CIPHER.decrypt(s['token']).decode(),'GET','/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member')
    return [dict(name=r['full_name'],private=r['private']) for r in rows]

def parse_repo(value):
    m=re.fullmatch(r'(?:https://github\.com/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?',value.strip())
    if not m: raise HTTPException(422,'Enter a GitHub URL or owner/repository.')
    owner,repo=m.groups(); repo=repo[:-4] if repo.endswith('.git') else repo
    if repo in ('','.','..'): raise HTTPException(422,'Invalid repository.')
    return owner+'/'+repo

def update(scan_id,status,data=None):
    with db() as c:
        if data is None: c.execute('UPDATE scans SET status=? WHERE id=?',(status,scan_id))
        else: c.execute('UPDATE scans SET status=?,data=? WHERE id=?',(status,json.dumps(data),scan_id))

def download_files(repo,sha,token):
    with httpx.Client(timeout=60,follow_redirects=False) as client:
        with client.stream('GET',f'https://codeload.github.com/{repo}/zip/{sha}',headers={'Authorization':f'Bearer {token}'}) as response:
            response.raise_for_status(); chunks=[]; size=0
            for chunk in response.iter_bytes():
                size+=len(chunk)
                if size>25_000_000: raise RuntimeError('Compressed repository exceeds 25 MB.')
                chunks.append(chunk)
    files={}; total=0; skipped=0
    with zipfile.ZipFile(io.BytesIO(b''.join(chunks))) as archive:
        if len(archive.infolist())>20000: raise RuntimeError('Too many archive entries.')
        for info in archive.infolist():
            path='/'.join(info.filename.split('/')[1:]); parts=path.split('/')
            if info.is_dir() or not path or '..' in parts or any(p in {'node_modules','.git','vendor','dist','build','.venv','venv'} for p in parts): continue
            if info.file_size>500000 or Path(path).suffix not in EXTENSIONS and Path(path).name!='.env': skipped+=1; continue
            total+=info.file_size
            if total>20000000 or len(files)>=2000: raise RuntimeError('Analysis exceeds 20 MB / 2,000 files.')
            files[path]=archive.read(info).decode('utf-8',errors='replace')
    return files,skipped

DEMO_FILES={'src/service.py':'import requests\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n\ndef start():\n    app.run(debug=True)\n\ndef pending():\n    # TODO: implement retries\n    pass\n\ntry:\n    run()\nexcept Exception:\n    pass\n','src/legacy.js':'// FIXME: validate input\nconst result = eval(userInput);\n'}

def run_scan(scan_id,repo,encrypted_token,is_demo):
    try:
        update(scan_id,'downloading'); token=CIPHER.decrypt(encrypted_token).decode()
        if is_demo: files,skipped,sha,branch=DEMO_FILES,0,'demo-snapshot','main'
        else:
            branch=gh(token,'GET',f'/repos/{repo}')['default_branch']
            sha=gh(token,'GET',f'/repos/{repo}/commits/{quote(branch,safe="")}')['sha']
            files,skipped=download_files(repo,sha,token)
        update(scan_id,'scanning'); findings=analyze(files)
        deps,status=([],'Sample scan: advisory lookups disabled.') if is_demo else check_dependencies(files)
        findings.extend(deps)
        update(scan_id,'completed',dict(findings=findings,commit=sha,branch=branch,files=len(files),skipped=skipped,demo=is_demo,coverage=['Heuristic security patterns','Credential patterns','Python AST checks','Loose-end markers','Repeated blocks',status],limitations=['Dependency checks cover exact requirements.txt pins and npm package-lock v2/v3.','Heuristic findings require human review.','No findings does not establish security.']))
    except Exception as error:
        update(scan_id,'failed',{'error':str(error) if isinstance(error,RuntimeError) else 'Repository access or analysis failed. Check access and retry.'})

class ScanInput(BaseModel): repo:str=Field(min_length=3,max_length=250)
class PRInput(BaseModel): findings:list[str]=Field(min_length=1,max_length=100)

@app.post('/api/scans')
def start_scan(request:Request,payload:ScanInput):
    s=session(request,True); repo=parse_repo(payload.repo)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM scans WHERE created<?',(time.time()-7*86400,))
        c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
        count=c.execute('SELECT count(*) FROM scans WHERE owner=? AND created>?',(s['owner'],time.time()-3600)).fetchone()[0]
        active=c.execute("SELECT count(*) FROM scans WHERE status IN ('queued','downloading','scanning')").fetchone()[0]
        if count>=10 or active>=6: raise HTTPException(429,'Scan capacity reached. Retry later.')
        scan_id=secrets.token_hex(12)
        c.execute('INSERT INTO scans VALUES(?,?,?,?,?,?)',(scan_id,s['owner'],repo,'queued','{}',time.time()))
    POOL.submit(run_scan,scan_id,repo,s['token'],json.loads(s['user']).get('demo',False))
    return {'id':scan_id}

@app.get('/api/scans')
def scans(request:Request):
    s=session(request)
    with db() as c: rows=c.execute('SELECT id,repo,status,created FROM scans WHERE owner=? ORDER BY created DESC LIMIT 50',(s['owner'],)).fetchall()
    return [dict(r) for r in rows]

def get_scan(request,scan_id,write=False):
    s=session(request,write)
    with db() as c: row=c.execute('SELECT * FROM scans WHERE id=? AND owner=?',(scan_id,s['owner'])).fetchone()
    if not row: raise HTTPException(404,'Scan not found.')
    return s,dict(row)

@app.get('/api/scans/{scan_id}')
def scan(request:Request,scan_id:str):
    _,row=get_scan(request,scan_id); row['data']=json.loads(row['data']); row.pop('owner'); return row

@app.post('/api/scans/{scan_id}/pull-request')
def pull_request(request:Request,scan_id:str,payload:PRInput):
    s,row=get_scan(request,scan_id,True); report=json.loads(row['data'])
    if row['status']!='completed' or report.get('demo'): raise HTTPException(400,'A completed live scan is required.')
    selected=set(payload.findings)
    fixes=[f for f in report['findings'] if f['id'] in selected and f.get('replacement') is not None]
    if not fixes: raise HTTPException(422,'Select at least one available fix.')
    if len({(f['path'],f['line']) for f in fixes})!=len(fixes): raise HTTPException(422,'Select one fix per source line, then rescan after merging.')
    token=CIPHER.decrypt(s['token']).decode(); repo=row['repo']
    try:
        files={}
        for fix in fixes:
            path=fix['path']
            if path not in files:
                content=gh(token,'GET',f'/repos/{repo}/contents/{quote(path,safe="/")}?ref={report["commit"]}')
                files[path]=base64.b64decode(content['content']).decode('utf-8')
        for fix in fixes:
            lines=files[fix['path']].splitlines(keepends=True)
            if SECRET.search(lines[fix['line']-1]): raise RuntimeError('Credential-line changes are blocked.')
            newline='\n' if lines[fix['line']-1].endswith('\n') else ''
            lines[fix['line']-1]=fix['replacement']+newline; files[fix['path']]=''.join(lines)
        branch='reposentry/'+scan_id+'-'+secrets.token_hex(3)
        tree=gh(token,'GET',f'/repos/{repo}/git/commits/{report["commit"]}')['tree']['sha']
        existing=gh(token,'GET',f'/repos/{repo}/git/trees/{tree}?recursive=1')
        if existing.get('truncated'): raise RuntimeError('Repository tree is too large for a safe automatic fix.')
        modes={e['path']:e['mode'] for e in existing['tree']}
        entries=[]
        for path,source in files.items():
            if modes.get(path) not in ('100644','100755'): raise RuntimeError('Only regular files can be automatically fixed.')
            blob=gh(token,'POST',f'/repos/{repo}/git/blobs',json={'content':source,'encoding':'utf-8'})
            entries.append(dict(path=path,mode=modes[path],type='blob',sha=blob['sha']))
        new_tree=gh(token,'POST',f'/repos/{repo}/git/trees',json=dict(base_tree=tree,tree=entries))
        commit=gh(token,'POST',f'/repos/{repo}/git/commits',json=dict(message='fix: apply reviewed RepoSentry recommendations',tree=new_tree['sha'],parents=[report['commit']]))
        gh(token,'POST',f'/repos/{repo}/git/refs',json={'ref':'refs/heads/'+branch,'sha':commit['sha']})
        pr=gh(token,'POST',f'/repos/{repo}/pulls',json=dict(title='fix: address RepoSentry findings',head=branch,base=report['branch'],body='Applies explicitly selected fixes from scan '+scan_id+'. Review behavior and run project tests before merging. Repository code was not executed.',draft=True))
        return {'url':pr['html_url']}
    except (RuntimeError,KeyError,ValueError) as error:
        raise HTTPException(409,str(error) if isinstance(error,RuntimeError) else 'Unable to prepare changes. Rescan and retry. A branch may exist.')

app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
@app.get('/')
def index(): return FileResponse(ROOT/'static/index.html')
