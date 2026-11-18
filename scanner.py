"""Deterministic, architecture-independent static review. Never executes source."""
import ast
import hashlib
import re

SECRET = re.compile(r'(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\'"]([^\'"\n]{12,})[\'"]|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b', re.I)
EXTENSIONS = {'.py','.js','.ts','.jsx','.tsx','.java','.go','.rb','.php','.rs','.yaml','.yml','.json','.env','.toml','.sh','.txt','.html','.css','.vue','.svelte'}
RULES = [
 ('dynamic-eval','high','security',r'\beval\s*\(','Dynamic code execution','Use explicit parsing instead of eval.',None),
 ('shell-execution','high','security',r'shell\s*=\s*True|\b(?:os\.system|child_process\.exec)\s*\(','Shell execution','Use validated argument arrays with shell disabled.',None),
 ('tls-verification','high','security',r'verify\s*=\s*False','TLS verification disabled','Enable certificate verification.','verify=True'),
 ('debug-enabled','medium','security',r'debug\s*=\s*True','Debug mode enabled','Disable debug mode in production.','debug=False'),
 ('unfinished','low','loose-ends',r'\b(?:TODO|FIXME|HACK)\b','Unfinished work marker','Complete the work or track it in an issue.',None),
 ('placeholder','medium','loose-ends',r'raise\s+NotImplementedError','Unimplemented code','Implement the behavior and add a regression test.',None),
]

def analyze(files):
    results, blocks = [], {}
    def add(path,line,rule,severity,category,title,evidence,advice,replacement=None):
        results.append(dict(id=hashlib.sha256(f'{path}:{line}:{rule}'.encode()).hexdigest()[:16],path=path,line=line,rule=rule,severity=severity,category=category,title=title,evidence=evidence[:240],advice=advice,replacement=replacement,confidence='heuristic'))
    for path,source in files.items():
        lines=source.splitlines()
        for number,line in enumerate(lines,1):
            if SECRET.search(line):
                add(path,number,'secret','critical','security','Possible hardcoded credential','[REDACTED: possible credential]','Revoke and rotate this credential; move it to a secret manager.')
                continue
            for rule,severity,category,pattern,title,advice,fix in RULES:
                if re.search(pattern,line):
                    add(path,number,rule,severity,category,title,line.strip(),advice,re.sub(pattern,fix,line) if fix else None)
        if path.endswith('.py'):
            try:
                tree=ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node,ast.ExceptHandler) and all(isinstance(n,ast.Pass) for n in node.body):
                        add(path,node.lineno,'swallowed-exception','medium','loose-ends','Exception silently discarded',lines[node.lineno-1].strip(),'Handle the error explicitly or re-raise it.')
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        body=[n for n in node.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str))]
                        if body and all(isinstance(n,ast.Pass) for n in body):
                            add(path,node.lineno,'empty-function','medium','loose-ends','Empty function',lines[node.lineno-1].strip(),'Implement this function or document its intentional empty behavior.')
                        count=sum(isinstance(n,(ast.If,ast.For,ast.While,ast.Try,ast.IfExp)) for n in ast.walk(node))
                        if count>10:
                            add(path,node.lineno,'complexity','medium','quality','Complex function',lines[node.lineno-1].strip(),f'Review {count} branching constructs and consider smaller functions.')
            except SyntaxError:
                add(path,1,'syntax','medium','quality','Python syntax could not be parsed','','Check syntax and project Python version.')
        for i in range(0,max(0,len(lines)-7),8):
            block='\n'.join(l.strip() for l in lines[i:i+8] if l.strip())
            if len(block)<180 or SECRET.search(block): continue
            if block in blocks:
                add(path,i+1,'duplication','low','quality','Repeated code block',lines[i].strip(),'Review duplication with '+blocks[block])
            else: blocks[block]=f'{path}:{i+1}'
    from source_checks import inspect_sources
    results.extend(inspect_sources(files))
    return sorted(results,key=lambda f:['critical','high','medium','low'].index(f['severity']))
