import hashlib
import json
import re
import httpx

def check(files):
    packages=[]
    for path,source in files.items():
        if path.endswith('requirements.txt'):
            for number,line in enumerate(source.splitlines(),1):
                m=re.match(r'^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(?:#.*)?$',line)
                if m: packages.append((path,number,'PyPI',*m.groups()))
        elif path.endswith('package-lock.json'):
            try:
                for name,entry in json.loads(source).get('packages',{}).items():
                    if 'node_modules/' in name and entry.get('version'):
                        packages.append((path,1,'npm',name.rsplit('node_modules/',1)[1],entry['version']))
            except (ValueError,AttributeError,TypeError): pass
    if not packages: return [],'No supported exact dependency pins found.'
    truncated=len(packages)>300
    packages=packages[:300]
    try:
        with httpx.Client(timeout=25) as client:
            response=client.post('https://api.osv.dev/v1/querybatch',json={'queries':[{'package':{'name':name,'ecosystem':eco},'version':version} for _,_,eco,name,version in packages]})
            response.raise_for_status()
            results=response.json()['results']
        findings=[]
        for (path,line,eco,name,version),result in zip(packages,results):
            for advisory in result.get('vulns',[]):
                aid=advisory['id']
                findings.append(dict(id=hashlib.sha256(f'{path}:{name}:{aid}'.encode()).hexdigest()[:16],path=path,line=line,rule='dependency-advisory',severity='medium',category='security',title='Known dependency advisory: '+name,evidence=f'{name}=={version} · {aid}',advice=f'Review https://osv.dev/vulnerability/{aid} and upgrade to an unaffected version. Medium is a review priority, not a CVSS rating.',replacement=None,confidence='advisory-match'))
        return findings,f'OSV checked {len(packages)} pinned dependencies.'+(' Limit reached; remaining packages were not checked.' if truncated else '')
    except (httpx.HTTPError,ValueError,KeyError,TypeError):
        return [],'Dependency lookup unavailable; advisory coverage is incomplete.'
