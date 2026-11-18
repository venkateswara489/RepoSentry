const $=id=>document.getElementById(id);
let auth=null,current=null,poll=null;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,options={}) {
  const r=await fetch(path,{...options,headers:{'Content-Type':'application/json',...(auth?{'X-CSRF-Token':auth.csrf}:{}),...options.headers}});
  const data=await r.json();
  if(!r.ok)throw new Error(typeof data.detail==='string'?data.detail:'Request failed. Check the input and retry.');
  return data;
}
function notice(message){$('notice').textContent=message;$('notice').hidden=!message;}
async function history(){
  if(!auth)return;
  try{
    const rows=await api('/api/scans');
    $('history-list').className=rows.length?'':'empty';
    $('history-list').innerHTML=rows.length?rows.map(r=>`<button class="history-row" data-scan="${esc(r.id)}"><strong>${esc(r.repo)}</strong><small>${new Date(r.created*1000).toLocaleString()}</small><span class="badge ${esc(r.status)}">${esc(r.status)}</span></button>`).join(''):'No scans yet. Start with a repository or try the sample.';
    document.querySelectorAll('[data-scan]').forEach(b=>b.onclick=()=>load(b.dataset.scan));
  }catch(e){notice(e.message);}
}
function busy(value){$('scan-button').disabled=value;$('sample-button').disabled=value;}
async function load(id){
  clearTimeout(poll);
  try{
    current=await api('/api/scans/'+id);
    const pending=['queued','downloading','scanning'].includes(current.status);
    $('progress').hidden=!pending;busy(pending);
    if(pending){
      $('results').hidden=true;
      $('progress-title').textContent=({queued:'1 / 3 · Waiting for a worker',downloading:'2 / 3 · Reading a pinned source snapshot',scanning:'3 / 3 · Checking source and dependency advisories'})[current.status];
      poll=setTimeout(()=>load(id),1200);return;
    }
    await history();
    if(current.status==='failed'){notice(current.data.error||'Scan interrupted. Please retry.');return;}
    notice('');$('results').hidden=false;$('welcome').hidden=true;
    const data=current.data,summary=data.summary;
    $('result-repo').textContent=current.repo;
    $('result-meta').textContent=`${data.demo?'SAMPLE DATA · ':''}${data.files} files analyzed · ${data.skipped} skipped · commit ${data.commit.slice(0,12)}`;
    $('report-summary').innerHTML=`<strong>${summary.action_areas} action areas to review</strong><p>${summary.dependency_packages} affected dependency groups · ${summary.advisory_records} advisory records · ${summary.advisory_groups} issue groups based on available aliases.</p><p>Counts describe review candidates, not proven exploits. Unknown means no verified severity was available. Start with source findings and published high-priority advisories; validate each in context.</p>`;
    $('stats').innerHTML=['critical','high','medium','low','unknown'].map(s=>`<div class="stat ${s}"><span>${s==='unknown'?'Unknown severity':s}</span><strong>${summary.severities[s]||0}</strong><small>action areas</small></div>`).join('');
    $('coverage').innerHTML='<ul>'+[...data.coverage,...data.limitations].map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>';
    render();
  }catch(e){notice(e.message);$('progress').hidden=true;busy(false);}
}
function advisoryMarkup(f){
  if(!f.advisories)return '';
  return `<details class="advisories"><summary>Inspect ${f.advisories.length} advisory groups (${f.raw_advisory_count} source records)</summary>${f.advisories.map(a=>`<div class="advisory"><a target="_blank" rel="noopener noreferrer" href="https://osv.dev/vulnerability/${encodeURIComponent(a.id)}">${esc(a.id)} ↗</a><span class="severity ${esc(a.severity)}">${esc(a.severity)}</span><p>${esc(a.summary)}</p>${a.aliases.length?`<p>Related IDs: ${a.aliases.map(esc).join(', ')}</p>`:''}<p>${a.fixed_versions.length?'Fix releases reported by advisory: '+a.fixed_versions.map(esc).join(', '):'No fixed release information available in this report.'}</p></div>`).join('')}</details>`;
}
function card(f){
  const source=current.data.demo?`<span class="source">${esc(f.path)}:${f.line}</span>`:`<a target="_blank" rel="noopener noreferrer" class="source" href="https://github.com/${esc(current.repo)}/blob/${esc(current.data.commit)}/${f.path.split('/').map(encodeURIComponent).join('/')}#L${f.line}">${esc(f.path)}:${f.line} ↗</a>`;
  return `<article class="finding"><div class="finding-top"><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span><h3>${esc(f.title)}</h3><span class="tag">${esc(f.category)}</span></div>${source}<pre>${esc(f.evidence)}</pre><h4>What this means</h4><p>${esc(f.explanation)}</p><h4>What to do next</h4><p>${esc(f.advice)}</p>${f.replacement?`<details><summary>Suggested code change — review before using</summary><pre>${esc(f.replacement)}</pre><p>This suggestion has not been executed or tested against your project.</p></details>`:''}<p class="severity-note">${esc(f.severity_basis)} · ${esc(f.confidence)}</p>${advisoryMarkup(f)}</article>`;
}
function render(){
  if(!current||current.status!=='completed')return;
  const query=$('search').value.trim().toLowerCase();
  const findings=current.data.findings.filter(f=>($('severity').value==='all'||f.severity===$('severity').value)&&($('category').value==='all'||f.category===$('category').value)&&(!query||[f.title,f.path,f.rule,f.evidence].join(' ').toLowerCase().includes(query)));
  $('finding-count').textContent=findings.length;
  $('findings').innerHTML=findings.length?findings.map(card).join(''):'<div class="empty">No matching action areas. A clean report does not establish security.</div>';
}
async function start(sample=false){
  notice('');if(!auth){notice('Preparing browser session. Refresh and retry.');return;}
  try{busy(true);const r=await api('/api/scans',{method:'POST',body:JSON.stringify({repo:sample?'sample/storefront':$('repo').value,sample})});await load(r.id);}
  catch(e){notice(e.message);busy(false);}
}
$('scan-form').onsubmit=e=>{e.preventDefault();start();};
$('sample-button').onclick=()=>start(true);
$('severity').onchange=render;$('category').onchange=render;$('search').oninput=render;
$('refresh').onclick=history;$('history-link').onclick=()=>$('history').scrollIntoView({behavior:'smooth'});$('overview').onclick=()=>window.scrollTo({top:0,behavior:'smooth'});
function save(content,type,suffix){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download='reposentry-'+current.id+'.'+suffix;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('export').onclick=()=>{if(current?.status==='completed')save(JSON.stringify(current,null,2),'application/json','json');};
$('export-html').onclick=()=>{
  if(current?.status!=='completed')return;
  const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'"><title>RepoSentry report</title></head><body><h1>RepoSentry: ${esc(current.repo)}</h1><p>Commit ${esc(current.data.commit)} · ${current.data.summary.action_areas} action areas · ${current.data.files} files analyzed</p><p>Static review candidates, not confirmed exploits. Review in context.</p>${current.data.findings.map(card).join('')}<h2>Coverage & limitations</h2>${$('coverage').innerHTML}</body></html>`;
  save(html,'text/html','html');
};
(async()=>{try{auth=await api('/api/session');const config=await api('/api/config');if(config.demoEnabled){$('repo').value='sample/storefront';$('connect-note').textContent='Sample mode: fixed fixture only; no repository is accessed.';}await history();}catch(e){notice(e.message);}})();
