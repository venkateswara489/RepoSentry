"""Bounded OSV lookup, alias-aware deduplication, and package-level findings."""
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
import httpx

LEVELS = ('critical', 'high', 'medium', 'low')

def merge_advisories(records):
    """Connected components over IDs and aliases; preserve unknown severity."""
    groups = []
    for record in records:
        ids = {record['id'], *record.get('aliases', [])}
        matches = [g for g in groups if ids & g['ids']]
        combined = {'ids': ids, 'records': [record]}
        for group in matches:
            combined['ids'].update(group['ids'])
            combined['records'].extend(group['records'])
            groups.remove(group)
        groups.append(combined)
    output = []
    for group in groups:
        rows = group['records']
        severities = [str(r.get('database_specific', {}).get('severity', '')).lower() for r in rows]
        severity = next((level for level in LEVELS if level in severities), 'unknown')
        fixed = sorted({event['fixed'] for r in rows for affected in r.get('affected', [])
                        for interval in affected.get('ranges', []) for event in interval.get('events', []) if event.get('fixed')})
        output.append({'id': rows[0]['id'], 'aliases': sorted(group['ids'] - {rows[0]['id']}),
                       'summary': next((r.get('summary') for r in rows if r.get('summary')), 'Published advisory; review affected usage.'),
                       'severity': severity, 'fixed_versions': fixed,
                       'url': 'https://osv.dev/vulnerability/' + rows[0]['id']})
    return output

def check(files):
    packages = []
    for path, source in files.items():
        if path.endswith('requirements.txt'):
            for number, line in enumerate(source.splitlines(), 1):
                match = re.match(r'^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(?:#.*)?$', line)
                if match: packages.append((path, number, 'PyPI', *match.groups()))
        elif path.endswith('package-lock.json'):
            try:
                for name, entry in json.loads(source).get('packages', {}).items():
                    if 'node_modules/' in name and entry.get('version'):
                        packages.append((path, 1, 'npm', name.rsplit('node_modules/', 1)[1], entry['version']))
            except (ValueError, AttributeError, TypeError): pass
    if not packages: return [], 'No supported exact dependency pins found.'
    truncated = len(packages) > 300
    packages = list(dict.fromkeys(packages))[:300]
    try:
        with httpx.Client(timeout=15) as client:
            response = client.post('https://api.osv.dev/v1/querybatch', json={'queries': [
                {'package': {'name': name, 'ecosystem': eco}, 'version': version} for _, _, eco, name, version in packages]})
            response.raise_for_status()
            results = response.json()['results']
            ids = list(dict.fromkeys(v['id'] for result in results for v in result.get('vulns', [])))
            # Enrichment is bounded; querybatch results still survive unavailable details.
            def detail(aid):
                if not re.fullmatch(r'[A-Za-z0-9_.-]+', aid): return aid, None
                try:
                    r = client.get('https://api.osv.dev/v1/vulns/' + aid)
                    r.raise_for_status()
                    payload = r.json()
                    return aid, payload if isinstance(payload, dict) and payload.get('id') == aid else None
                except (httpx.HTTPError, ValueError): return aid, None
            with ThreadPoolExecutor(max_workers=8) as pool:
                details = dict(pool.map(detail, ids[:40]))
        findings = []
        for (path, line, eco, name, version), result in zip(packages, results):
            records = [details.get(v['id']) or v for v in result.get('vulns', [])]
            if not records: continue
            records = [dict(r, affected=[a for a in r.get('affected', [])
                if a.get('package', {}).get('ecosystem') == eco
                and re.sub(r'[-_.]+', '-', a.get('package', {}).get('name', '')).lower() == re.sub(r'[-_.]+', '-', name).lower()]) for r in records]
            advisories = merge_advisories(records)
            severity = next((level for level in LEVELS if any(a['severity'] == level for a in advisories)), 'unknown')
            findings.append(dict(id=hashlib.sha256(f'{path}:{eco}:{name}:{version}'.encode()).hexdigest()[:16],
                path=path, line=line, rule='dependency-advisory', severity=severity, category='security',
                title=f'Review dependency: {name}', package=name, version=version, ecosystem=eco,
                evidence=f'{name}=={version}', advice='Review the advisory links, choose a release that addresses all applicable advisories, then test compatibility. Listed fixed versions may belong to different release branches.',
                explanation=f'{len(records)} advisory records grouped into {len(advisories)} known issue groups for this package. Applicability to your application has not been verified.',
                replacement=None, confidence='advisory-match', advisories=advisories, raw_advisory_count=len(records),
                severity_basis='Highest published database severity in available records; unknown when absent. CVSS vectors are not calculated.'))
        status=f'OSV checked {len(packages)} pinned dependencies; enriched {sum(v is not None for v in details.values())}/{len(ids)} advisory records (maximum 40). Alias deduplication is limited to available details.'
        if truncated: status+=' Package limit reached; remaining pins were not checked.'
        return findings, status
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return [], 'Dependency lookup unavailable; advisory coverage is incomplete.'
