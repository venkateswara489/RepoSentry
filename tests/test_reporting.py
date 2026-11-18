from dependencies import merge_advisories
from reporting import prepare_report

def test_alias_merge_is_transitive_and_preserves_severity():
    rows=[{'id':'GHSA-one','aliases':['CVE-1'],'database_specific':{'severity':'HIGH'}},
          {'id':'PYSEC-two','aliases':['CVE-2']},
          {'id':'bridge','aliases':['CVE-1','CVE-2']}]
    groups=merge_advisories(rows)
    assert len(groups)==1
    assert groups[0]['severity']=='high'
    assert {groups[0]['id'], *groups[0]['aliases']}=={'CVE-1','CVE-2','PYSEC-two','bridge','GHSA-one'}

def test_cvss_vector_is_not_mislabeled_medium():
    group=merge_advisories([{'id':'GHSA-a','severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]}])[0]
    assert group['severity']=='unknown'

def test_legacy_174_records_become_seven_action_areas():
    rows=[dict(id='debug',path='app.py',line=44,rule='debug-enabled',severity='medium',title='Debug enabled',evidence='debug=True',advice='Disable in production.')]
    for name,count in [('nltk',97),('transformers',46),('torch',24),('flask',2),('PyPDF2',2),('scikit-learn',2)]:
        rows += [dict(id=f'{name}-{i}',path='requirements.txt',line=1,rule='dependency-advisory',severity='medium',title=name,evidence=f'{name}==1.0 · TEST-{name}-{i}',advice='Review.') for i in range(count)]
    data=prepare_report({'findings':rows})
    assert data['summary']['action_areas']==7
    assert data['summary']['advisory_records']==173
    assert data['summary']['severities']=={'medium':1,'unknown':6}
    assert len(rows)==174 # no mutation of stored data
    assert prepare_report(data)==data

def test_published_severity_and_fixed_versions():
    rows=[{'id':'TEST-1','database_specific':{'severity':'CRITICAL'},'affected':[{'ranges':[{'events':[{'introduced':'0'},{'fixed':'2.0'}]}]}]}]
    group=merge_advisories(rows)[0]
    assert group['severity']=='critical'
    assert group['fixed_versions']==['2.0']

def test_enriched_package_groups_aliases_and_uses_correct_fixed_version(monkeypatch):
    import httpx
    import dependencies
    first={'id':'GHSA-one','aliases':['CVE-1'],'summary':'Unsafe parsing','database_specific':{'severity':'HIGH'},'affected':[
        {'package':{'name':'example','ecosystem':'PyPI'},'ranges':[{'events':[{'fixed':'2.0'}]}]},
        {'package':{'name':'other','ecosystem':'PyPI'},'ranges':[{'events':[{'fixed':'99.0'}]}]}]}
    second={'id':'PYSEC-two','aliases':['CVE-1']}
    def respond(request):
        if request.method=='POST': return httpx.Response(200,json={'results':[{'vulns':[{'id':'GHSA-one'},{'id':'PYSEC-two'}]}]})
        return httpx.Response(200,json=first if request.url.path.endswith('GHSA-one') else second)
    real_client=httpx.Client
    monkeypatch.setattr(dependencies.httpx,'Client',lambda **kw:real_client(transport=httpx.MockTransport(respond),**kw))
    findings,status=dependencies.check({'requirements.txt':'example==1.0\n'})
    assert len(findings)==1
    assert findings[0]['severity']=='high'
    assert findings[0]['raw_advisory_count']==2
    assert len(findings[0]['advisories'])==1
    assert findings[0]['advisories'][0]['fixed_versions']==['2.0']
    assert '2/2' in status
