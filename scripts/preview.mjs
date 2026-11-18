import {spawn} from 'node:child_process';
const args=process.argv.slice(2).filter(a=>a!=='--strictPort');
const child=spawn('.venv/bin/python',['-m','uvicorn','app:app',...args],{stdio:'inherit',env:{...process.env,DEMO_MODE:'true'}});
process.on('SIGTERM',()=>child.kill('SIGTERM'));child.on('exit',code=>process.exit(code||0));
