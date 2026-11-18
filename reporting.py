"""Versioned, explanatory reports; also upgrades legacy reports on read."""
from collections import Counter
import copy

ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}

def prepare_report(data):
    data = copy.deepcopy(data)
    findings = data.get('findings', [])
    grouped, other = {}, []
    for f in findings:
        if f.get('rule') != 'dependency-advisory' or 'advisories' in f:
            other.append(f)
            continue
        pin, _, aid = f.get('evidence', '').partition(' · ')
        name, _, version = pin.partition('==')
        key = (f['path'], name, version)
        if key not in grouped:
            grouped[key] = dict(f, title='Review dependency: '+name, package=name, version=version,
                severity='unknown', evidence=pin, advisories=[], raw_advisory_count=0,
                explanation='Legacy advisory records grouped by package. Alias overlap and actual severity could not be determined from this saved report. Rescan for enriched details.',
                advice='Review advisories, upgrade to a compatible unaffected release, and run project tests.',
                severity_basis='Legacy default medium priority replaced with unknown; no verified severity was stored.')
        group = grouped[key]
        group['raw_advisory_count'] += 1
        if aid and not any(a['id'] == aid for a in group['advisories']):
            group['advisories'].append(dict(id=aid, aliases=[], summary='Legacy advisory; open source for details.', severity='unknown', fixed_versions=[], url='https://osv.dev/vulnerability/'+aid))
    findings = other + list(grouped.values())
    for f in findings:
        f.setdefault('explanation', {'debug-enabled':'Development debug mode is enabled. This can expose internals if deployed publicly; local-only use may be intentional.',
            'secret':'A credential-like value was found. This is a pattern match, not proof that the credential is valid.',
            'unfinished':'An unfinished-work marker was found. It may be intentional and is not automatically a defect.'}.get(f.get('rule'), 'A static check matched this code. Review the evidence and project context before changing it.'))
        f.setdefault('severity_basis', 'Static rule priority; exploitability has not been established.')
    findings.sort(key=lambda f: ORDER.get(f.get('severity'), 4))
    raw = sum(f.get('raw_advisory_count', 0) for f in findings)
    summary = dict(action_areas=len(findings), dependency_packages=sum('advisories' in f for f in findings),
        advisory_records=raw, advisory_groups=sum(len(f.get('advisories', [])) for f in findings),
        severities=dict(Counter(f['severity'] for f in findings)))
    data.update(schema_version=2, findings=findings, summary=summary)
    return data
