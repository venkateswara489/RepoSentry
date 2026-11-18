from scanner import analyze
from source_checks import inventory

def rules(source,path='app.py'):
    return {f['rule'] for f in analyze({path:source})}

def test_exception_disclosure_and_unused_import():
    source='import tempfile\n\ndef route():\n    try:\n        run()\n    except Exception as error:\n        return {"error": str(error)}\n'
    assert {'unused-import','exception-disclosure'} <= rules(source)

def test_no_disclosure_when_exception_is_logged_not_returned():
    source='def route():\n    try:\n        run()\n    except Exception as error:\n        print(str(error))\n        return {"error": "Request failed"}\n'
    assert 'exception-disclosure' not in rules(source)

def test_runtime_downloads_defaults_and_timeouts():
    source='import nltk\nimport requests as req\ndef fetch(url, cache={}):\n    nltk.download("punkt")\n    return req.get(url)\n'
    assert {'runtime-download','mutable-default','http-timeout'} <= rules(source)
    assert 'http-timeout' not in rules('import requests\nrequests.get(url, timeout=5)\n')

def test_deserialization_safe_yaml_and_sql():
    assert 'unsafe-deserialization' in rules('import pickle\npickle.loads(payload)')
    assert 'unsafe-deserialization' not in rules('import yaml\nyaml.load(value, Loader=yaml.SafeLoader)')
    assert 'sql-construction' in rules('cursor.execute(f"SELECT * FROM users WHERE id={value}")')
    assert 'sql-construction' not in rules('cursor.execute("SELECT * FROM users WHERE id=?", (value,))')

def test_js_html_and_empty_catch():
    assert {'dom-html','empty-catch'} <= rules('output.innerHTML = value;\ntry { run(); } catch(error) {}','src/main.js')
    assert 'dom-html' not in rules('output.textContent = value;','src/main.js')

def test_scope_inventory_is_not_a_test_failure_claim():
    result=inventory({'app.py':'print(1)','templates/index.html':'<h1>hi</h1>','tests/test_app.py':'assert True'})
    assert result['test_file_count']==1
    assert result['languages']['Python']==2
    assert len(result['files'])==3

def test_new_checks_do_not_leak_credentials():
    secret='fake-password-value-123456'
    # Generic credential matcher still redacts directly assigned values.
    findings=analyze({'app.js':f'password="{secret}"; node.innerHTML=value;'})
    assert secret not in str(findings)
