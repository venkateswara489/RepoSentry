"""Additional explainable source checks. Candidates require human review."""
import ast
import hashlib
import re
from collections import Counter
from pathlib import Path

CHECK_NAMES = ['Python exception handling', 'Python imports and defaults', 'HTTP timeout checks',
               'Unsafe deserialization', 'Runtime downloads', 'SQL construction candidates',
               'JavaScript DOM sinks and empty catches', 'Function size', 'Repository test signals']

def inspect_sources(files):
    results=[]
    def add(path,line,rule,title,category,severity,why,fix,confidence='syntax-match'):
        lines=files.get(path,'').splitlines()
        evidence=lines[line-1].strip() if 0<line<=len(lines) else ''
        results.append(dict(id=hashlib.sha256(f'{path}:{line}:{rule}'.encode()).hexdigest()[:16],path=path,line=line,rule=rule,
            title=title,category=category,severity=severity,evidence=evidence[:240],explanation=why,advice=fix,
            confidence=confidence,replacement=None,severity_basis='Static review priority; application reachability and exploitability are not established.'))
    for path,source in files.items():
        if path.endswith('.py'):
            try: tree=ast.parse(source)
            except (SyntaxError,RecursionError): continue
            aliases={}
            imports=[]
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):
                    for a in node.names:
                        name=a.asname or a.name.split('.')[0]; aliases[name]=a.name; imports.append((name,node.lineno))
                elif isinstance(node,ast.ImportFrom) and node.module:
                    for a in node.names:
                        if a.name!='*':
                            name=a.asname or a.name; aliases[name]=node.module+'.'+a.name; imports.append((name,node.lineno))
            used={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}
            if not path.endswith('__init__.py'):
                for name,line in imports:
                    if name not in used and name!='annotations':
                        add(path,line,'unused-import','Possibly unused import: '+name,'quality','low',
                            'This import is not referenced as a loaded name in this file. It may still be used for side effects or re-exporting.',
                            'Remove the import if unnecessary; retain and document intentional side effects or exports.')
            def name(node):
                if isinstance(node,ast.Name): return aliases.get(node.id,node.id)
                if isinstance(node,ast.Attribute): return name(node.value)+'.'+node.attr
                return ''
            for node in ast.walk(tree):
                if isinstance(node,ast.ExceptHandler):
                    if node.type is None:
                        add(path,node.lineno,'bare-except','Bare except catches process-exit signals','loose-ends','medium',
                            'An unqualified except catches KeyboardInterrupt and SystemExit as well as ordinary failures.',
                            'Catch the expected exception classes; handle cleanup explicitly.')
                    if node.name:
                        for returned in (n for n in ast.walk(node) if isinstance(n,ast.Return)):
                            calls=[n for n in ast.walk(returned) if isinstance(n,ast.Call)]
                            if any(name(c.func)=='str' and c.args and isinstance(c.args[0],ast.Name) and c.args[0].id==node.name for c in calls):
                                add(path,returned.lineno,'exception-disclosure','Raw exception text returned to caller','security','medium',
                                    'The handler returns str(exception). In a web response this can reveal internal paths, database details, or implementation information. Context matters.',
                                    'Return a stable public error message and log details server-side with a request ID. Test that responses omit internal exception text.')
                            elif isinstance(returned.value,ast.Constant) and returned.value.value in ('',None,False):
                                add(path,returned.lineno,'error-sentinel','Failure is converted to an ordinary empty result','loose-ends','low',
                                    'This handler turns a failure into an empty value, making an error difficult for callers to distinguish from valid empty data.',
                                    'Return an explicit error result or raise a domain-specific exception; test both empty input and processing failure.')
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    defaults=node.args.defaults+[d for d in node.args.kw_defaults if d is not None]
                    if any(isinstance(d,(ast.List,ast.Dict,ast.Set)) for d in defaults):
                        add(path,node.lineno,'mutable-default','Mutable function default is shared across calls','quality','medium',
                            'Python evaluates default arguments once. Mutating a default list, dict, or set can leak state between calls.',
                            'Use None as the default and create the collection inside the function. Test repeated calls.')
                    if getattr(node,'end_lineno',node.lineno)-node.lineno>60:
                        add(path,node.lineno,'long-function','Long function deserves decomposition','quality','low',
                            f'This function spans {node.end_lineno-node.lineno+1} lines. Length is a maintainability signal, not a correctness defect.',
                            'Extract coherent responsibilities where this improves readability, retaining behavior with tests.')
                if not isinstance(node,ast.Call): continue
                call=name(node.func); keywords={k.arg for k in node.keywords}
                if re.fullmatch(r'(requests|httpx)\.(get|post|put|patch|delete|head|request)',call) and 'timeout' not in keywords:
                    add(path,node.lineno,'http-timeout','HTTP call has no explicit timeout','quality','medium',
                        'No timeout keyword is present at this call. Requests may block indefinitely; httpx has defaults but an explicit project timeout improves predictability.',
                        'Set a suitable connect/read timeout and handle timeout exceptions. Verify behavior against a slow endpoint.')
                if call in ('pickle.load','pickle.loads','dill.load','dill.loads','yaml.load'):
                    if call=='yaml.load' and any(k.arg=='Loader' and name(k.value).endswith(('SafeLoader','CSafeLoader')) for k in node.keywords): continue
                    add(path,node.lineno,'unsafe-deserialization','Deserializer requires trusted input','security','high',
                        'This API can construct objects or execute code for unsafe inputs. The scanner has not established where the input originates.',
                        'Use a safe data format or safe YAML loader. Never deserialize attacker-controlled pickle data.')
                if call in ('nltk.download','spacy.cli.download'):
                    add(path,node.lineno,'runtime-download','Resource download occurs in application code','quality','medium',
                        'Downloading data at runtime makes startup/request processing depend on network access, mutable external resources, and write permissions.',
                        'Provision pinned resources during build/setup. Validate availability at startup and test offline operation.')
                if call.endswith(('.execute','.executemany')) and node.args and isinstance(node.args[0],(ast.JoinedStr,ast.BinOp)):
                    add(path,node.lineno,'sql-construction','SQL query is built through string interpolation','security','high',
                        'The query argument is an f-string or binary string expression. Untrusted interpolation can enable SQL injection; input flow is not proven.',
                        'Use parameterized queries for values and allowlists for identifiers. Test adversarial input.')
        elif Path(path).suffix in {'.js','.jsx','.ts','.tsx','.vue','.svelte','.html'}:
            for number,line in enumerate(source.splitlines(),1):
                if re.search(r'\.innerHTML\s*=|dangerouslySetInnerHTML\s*=',line):
                    add(path,number,'dom-html','HTML injection sink requires trusted or sanitized content','security','medium',
                        'This expression inserts HTML. Risk depends on whether untrusted data can reach it; the scanner does not perform data-flow analysis.',
                        'Prefer textContent for text, or sanitize HTML with a maintained allowlist sanitizer.', 'heuristic')
                if re.search(r'catch\s*\([^)]*\)\s*\{\s*\}',line):
                    add(path,number,'empty-catch','Empty catch silently discards a failure','loose-ends','medium',
                        'A catch block has no handling. This may hide failed requests or incomplete state transitions.',
                        'Handle the failure, rethrow it, or document why ignoring it is safe.', 'heuristic')
                if re.search(r'\b(?:var|let|const)\s+\w+\s*=\s*new\s+Function\s*\(',line):
                    add(path,number,'function-constructor','Dynamic Function constructor','security','high',
                        'Function constructs executable code from strings. Risk depends on the source of those strings.',
                        'Replace dynamic code generation with explicit parsing or a lookup table.', 'heuristic')
    # Never include raw credential-like lines introduced by these checks.
    from scanner import SECRET
    for finding in results:
        if SECRET.search(finding['evidence']): finding['evidence']='[REDACTED: possible credential]'
    return results

def inventory(files):
    languages=Counter()
    for path in files:
        ext=Path(path).suffix
        languages[{'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.html':'HTML','.css':'CSS'}.get(ext,'Config / other')]+=1
    tests=[p for p in files if re.search(r'(^|/)(tests?/|test_[^/]+|[^/]+[._](test|spec)\.)',p)]
    return dict(languages=dict(languages),test_files=tests[:30],test_file_count=len(tests),
                checks=CHECK_NAMES,scope='Only the bounded set of downloaded supported text files was inspected. Test-file detection is a naming heuristic.',
                files=[dict(path=p,lines=len(s.splitlines()),language='Python AST + patterns' if p.endswith('.py') else 'Text patterns / manifest checks') for p,s in files.items()][:200])
