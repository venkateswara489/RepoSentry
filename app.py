import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import time
import zipfile
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote
import httpx
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from scanner import analyze,EXTENSIONS
from dependencies import check as check_dependencies
from reporting import prepare_report
import explanations

ROOT=Path(__file__).parent
DATA=Path(os.getenv('DATA_DIR',str(ROOT/'work')))
DATA.mkdir(parents=True,exist_ok=True)
BASE=os.getenv('BASE_URL','http://localhost:8000').rstrip('/')
DEMO=os.getenv('DEMO_MODE','false').lower()=='true'
# Optional deployment credential. Never read a token from a browser request.
PUBLIC_GITHUB_TOKEN=os.getenv('PUBLIC_GITHUB_TOKEN','').strip()
POOL=ThreadPoolExecutor(max_workers=2)
AI_SLOTS=threading.BoundedSemaphore(2)
app=FastAPI(title='RepoSentry',docs_url='/api/docs')

@contextmanager
def db():
    c=sqlite3.connect(DATA/'reposentry.db',timeout=20); c.row_factory=sqlite3.Row
    try: yield c; c.commit()
    finally: c.close()

with db() as c:
    c.executescript("""CREATE TABLE IF NOT EXISTS visitors(id TEXT PRIMARY KEY,csrf TEXT,expires REAL);
CREATE TABLE IF NOT EXISTS public_scans(id TEXT PRIMARY KEY,owner TEXT,repo TEXT,status TEXT,data TEXT,created REAL);
CREATE TABLE IF NOT EXISTS ai_cache(owner TEXT, fingerprint TEXT, data TEXT, created REAL, PRIMARY KEY(owner,fingerprint));
CREATE TABLE IF NOT EXISTS ai_calls(owner TEXT, created REAL);
UPDATE public_scans SET status='failed' WHERE status IN ('queued','downloading','scanning');""")
    # Invalidate legacy OAuth sessions, including their stored encrypted tokens.
    for legacy in ('sessions','oauth'):
        if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(legacy,)).fetchone():
            c.execute('DELETE FROM '+legacy)

@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' https://avatars.githubusercontent.com; frame-ancestors 'none'; base-uri 'none'"
    if request.url.path.startswith('/api'): response.headers['Cache-Control']='no-store'
    return response

def session(request,write=False):
    sid=request.cookies.get('visitor','')
    with db() as c:
        row=c.execute('SELECT * FROM visitors WHERE id=? AND expires>?',(hashlib.sha256(sid.encode()).hexdigest(),time.time())).fetchone()
    if not row: raise HTTPException(401,'Refresh the page to initialize this browser session.')
    if write and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']):
        raise HTTPException(403,'Invalid request token. Refresh and retry.')
    result=dict(row); result['owner']=result['id']; return result

@app.get('/api/session')
def browser_session(request:Request):
    try:
        current=session(request)
        return {'csrf':current['csrf']}
    except HTTPException:
        pass
    sid,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    with db() as c:
        c.execute('DELETE FROM visitors WHERE expires<?',(time.time(),))
        c.execute('INSERT INTO visitors VALUES(?,?,?)',(hashlib.sha256(sid.encode()).hexdigest(),csrf,time.time()+7*86400))
    response=JSONResponse({'csrf':csrf})
    response.set_cookie('visitor',sid,httponly=True,secure=BASE.startswith('https:'),samesite='lax',max_age=7*86400)
    response.delete_cookie('session'); response.delete_cookie('oauth_state')
    return response

@app.get('/api/config')
def config(): return {'publicOnly':True,'demoEnabled':DEMO,'aiConfigured':bool(os.getenv('GROQ_API_KEY','').strip())}

def gh(path):
    headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
    if PUBLIC_GITHUB_TOKEN:
        headers['Authorization']='Bearer '+PUBLIC_GITHUB_TOKEN
    with httpx.Client(timeout=30,follow_redirects=False) as client:
        r=client.get('https://api.github.com'+path,headers=headers)
    if r.status_code==404:
        raise RuntimeError('Public repository not found. Private repositories are not supported.')
    if r.status_code==401:
        raise RuntimeError('The server GitHub token is invalid or expired. The operator must update PUBLIC_GITHUB_TOKEN in Render.')
    if r.status_code in (403,429):
        try:
            message=str(r.json().get('message','')).lower()
        except (ValueError,AttributeError):
            message=''
        limited=(r.status_code==429 or r.headers.get('x-ratelimit-remaining')=='0'
                 or 'retry-after' in r.headers or 'rate limit' in message)
        if limited:
            delay=None
            try:
                if r.headers.get('retry-after'):
                    delay=max(1,int(r.headers['retry-after']))
                elif r.headers.get('x-ratelimit-reset'):
                    delay=max(1,int(r.headers['x-ratelimit-reset'])-int(time.time()))
            except (ValueError,OverflowError):
                pass
            wait=f' Retry in about {(delay+59)//60} minute(s).' if delay else ' Retry later.'
            guidance=(' The server uses a shared unauthenticated IP quota; the operator can configure PUBLIC_GITHUB_TOKEN in Render.'
                      if not PUBLIC_GITHUB_TOKEN else ' The configured server token quota is exhausted or temporarily restricted.')
            raise RuntimeError('GitHub API rate limit reached.'+wait+guidance)
        raise RuntimeError('GitHub denied this server request (403). This is not a confirmed rate-limit response; check token permissions or GitHub access restrictions.')
    if r.status_code>=400:
        raise RuntimeError(f'GitHub returned {r.status_code}. Please retry later.')
    return r.json()

def parse_repo(value):
    m=re.fullmatch(r'(?:https://github\.com/)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?',value.strip())
    if not m: raise HTTPException(422,'Enter a GitHub URL or owner/repository.')
    owner,repo=m.groups(); repo=repo[:-4] if repo.endswith('.git') else repo
    if repo in ('','.','..'): raise HTTPException(422,'Invalid repository.')
    return owner+'/'+repo

def update(scan_id,status,data=None):
    with db() as c:
        if data is None: c.execute('UPDATE public_scans SET status=? WHERE id=?',(status,scan_id))
        else: c.execute('UPDATE public_scans SET status=?,data=? WHERE id=?',(status,json.dumps(data),scan_id))

def download_files(repo,sha):
    with httpx.Client(timeout=60,follow_redirects=False) as client:
        with client.stream('GET',f'https://codeload.github.com/{repo}/zip/{sha}') as response:
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

# Sample includes one quality candidate, without accessing a repository.
DEMO_FILES['src/complexity.py']='def calculate(value):\n'+''.join(f'    if value == {i}:\n        value += 1\n' for i in range(11))+'    return value\n'

def run_scan(scan_id,repo,is_demo):
    try:
        update(scan_id,'downloading')
        if is_demo: files,skipped,sha,branch=DEMO_FILES,0,'demo-snapshot','main'
        else:
            meta=gh(f'/repos/{repo}')
            if meta.get('private'):
                raise RuntimeError('Only public repositories are supported.')
            branch=meta['default_branch']
            sha=gh(f'/repos/{repo}/commits/{quote(branch,safe="")}')['sha']
            files,skipped=download_files(repo,sha)
        update(scan_id,'scanning'); findings=analyze(files)
        deps,status=([],'Sample scan: advisory lookups disabled.') if is_demo else check_dependencies(files)
        findings.extend(deps)
        update(scan_id,'completed',dict(findings=findings,commit=sha,branch=branch,files=len(files),skipped=skipped,demo=is_demo,coverage=['Heuristic security patterns','Credential patterns','Python AST checks','Loose-end markers','Repeated blocks',status],limitations=['Dependency checks cover exact requirements.txt pins and npm package-lock v2/v3.','Heuristic findings require human review.','No findings does not establish security.']))
    except Exception as error:
        update(scan_id,'failed',{'error':str(error) if isinstance(error,RuntimeError) else 'Repository access or analysis failed. Check access and retry.'})

class ScanInput(BaseModel):
    repo:str=Field(min_length=3,max_length=250)
    sample:bool=False

@app.post('/api/scans')
def start_scan(request:Request,payload:ScanInput):
    s=session(request,True); repo=parse_repo(payload.repo)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM public_scans WHERE created<?',(time.time()-7*86400,))
        c.execute('DELETE FROM visitors WHERE expires<?',(time.time(),))
        count=c.execute('SELECT count(*) FROM public_scans WHERE owner=? AND created>?',(s['owner'],time.time()-3600)).fetchone()[0]
        active=c.execute("SELECT count(*) FROM public_scans WHERE status IN ('queued','downloading','scanning')").fetchone()[0]
        if count>=10 or active>=6: raise HTTPException(429,'Scan capacity reached. Retry later.')
        scan_id=secrets.token_hex(12)
        c.execute('INSERT INTO public_scans VALUES(?,?,?,?,?,?)',(scan_id,s['owner'],repo,'queued','{}',time.time()))
    POOL.submit(run_scan,scan_id,repo,DEMO or payload.sample)
    return {'id':scan_id}

@app.get('/api/scans')
def scans(request:Request):
    s=session(request)
    with db() as c: rows=c.execute('SELECT id,repo,status,created FROM public_scans WHERE owner=? ORDER BY created DESC LIMIT 50',(s['owner'],)).fetchall()
    return [dict(r) for r in rows]

def get_scan(request,scan_id,write=False):
    s=session(request,write)
    with db() as c: row=c.execute('SELECT * FROM public_scans WHERE id=? AND owner=?',(scan_id,s['owner'])).fetchone()
    if not row: raise HTTPException(404,'Scan not found.')
    return s,dict(row)

@app.get('/api/scans/{scan_id}')
def scan(request:Request,scan_id:str):
    _,row=get_scan(request,scan_id); row['data']=json.loads(row['data'])
    if row['status']=='completed': row['data']=prepare_report(row['data'])
    row.pop('owner'); return row

@app.post('/api/scans/{scan_id}/findings/{finding_id}/explain')
def explain_finding(request:Request,scan_id:str,finding_id:str):
    s,row=get_scan(request,scan_id,True)
    if row['status']!='completed': raise HTTPException(409,'Wait for the scan to complete.')
    report=prepare_report(json.loads(row['data']))
    finding=next((f for f in report['findings'] if f['id']==finding_id),None)
    if not finding: raise HTTPException(404,'Finding not found.')
    if not os.getenv('GROQ_API_KEY','').strip():
        return explanations.fallback(finding,'Groq is not configured. Built-in guidance is shown.')
    fingerprint=explanations.cache_key(finding)
    with db() as c:
        cached=c.execute('SELECT data FROM ai_cache WHERE owner=? AND fingerprint=? AND created>?',(s['owner'],fingerprint,time.time()-7*86400)).fetchone()
    if cached: return dict(json.loads(cached['data']),cached=True)
    if not AI_SLOTS.acquire(blocking=False): raise HTTPException(429,'Explanation workers are busy. Please retry shortly.')
    try:
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('DELETE FROM ai_calls WHERE created<?',(time.time()-3600,))
            c.execute('DELETE FROM ai_cache WHERE created<?',(time.time()-7*86400,))
            own=c.execute('SELECT count(*) FROM ai_calls WHERE owner=?',(s['owner'],)).fetchone()[0]
            total=c.execute('SELECT count(*) FROM ai_calls').fetchone()[0]
            if own>=20 or total>=60: raise HTTPException(429,'Explanation limit reached. Try again later; built-in recommendations remain available.')
            c.execute('INSERT INTO ai_calls VALUES(?,?)',(s['owner'],time.time()))
        result=explanations.generate(finding)
        if result['status']=='generated':
            with db() as c:
                c.execute('INSERT OR REPLACE INTO ai_cache VALUES(?,?,?,?)',(s['owner'],fingerprint,json.dumps(result),time.time()))
        return dict(result,cached=False)
    finally:
        AI_SLOTS.release()

app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
@app.get('/')
def index(): return FileResponse(ROOT/'static/index.html')
