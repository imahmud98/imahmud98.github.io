function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fileIcon(n){const e=(n||'').split('.').pop().toLowerCase();if(e==='pdf')return'PDF';if(['jpg','jpeg','png','gif','webp'].includes(e))return'IMG';if(['mp4','mov','webm','mkv'].includes(e))return'VID';if(['mp3','wav','flac'].includes(e))return'AUD';if(['zip','rar','7z'].includes(e))return'ZIP';if(['doc','docx'].includes(e))return'DOC';if(['xls','xlsx','csv'].includes(e))return'XLS';return'FILE'}
function fmtSize(b){b=Number(b||0);if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
function fmtDate(iso){if(!iso)return'';const d=new Date(iso);return d.toLocaleString(undefined,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}
let _tt;function toast(msg,type='info'){const el=document.getElementById('toast');el.style.background=type==='error'?'#dc2626':type==='success'?'#16a34a':'#0D6D6E';el.textContent=msg;el.style.display='block';clearTimeout(_tt);_tt=setTimeout(()=>{el.style.display='none'},4000)}
function showPanel(name){['loading','error','password','files'].forEach(p=>{const el=document.getElementById('panel-'+p);if(el)el.classList.toggle('hidden',p!==name)})}
function showError(title,msg){document.getElementById('error-title').textContent=title;document.getElementById('error-msg').textContent=msg;showPanel('error')}
function getStoredAccessToken(){try{return localStorage.getItem('mpd_access_token')||''}catch(_){return''}}

const ShareCrypto={
 async importShareKey(rawKeyBuf){return crypto.subtle.importKey('raw',rawKeyBuf,{name:'AES-GCM',length:256},false,['decrypt'])},
 async deriveShareKeyFromPassword(password,kdfParams){const enc=new TextEncoder();const keyMat=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);const salt=new Uint8Array(b64urlDecode(kdfParams.salt));return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:kdfParams.iterations||600000,hash:kdfParams.hash||'SHA-256'},keyMat,{name:'AES-GCM',length:256},false,['decrypt'])},
 async unwrapFileKey(wrappedFileKeyB64,ivB64,shareKeyCryptoKey){const ciphertext=new Uint8Array(b64urlDecode(wrappedFileKeyB64));const iv=new Uint8Array(b64urlDecode(ivB64));return crypto.subtle.decrypt({name:'AES-GCM',iv},shareKeyCryptoKey,ciphertext)},
 async decryptBlob(encryptedBlob,fileKeyRaw){const buf=new Uint8Array(encryptedBlob);if(buf.length<28)throw new Error('Encrypted blob is corrupted');const iv=buf.slice(16,28);const ct=buf.slice(28);const cryptoKey=await crypto.subtle.importKey('raw',fileKeyRaw,{name:'AES-GCM',length:256},false,['decrypt']);return crypto.subtle.decrypt({name:'AES-GCM',iv},cryptoKey,ct)}
};

const State={shareId:null,shareMeta:null,shareKey:null,rawShareKey:null,apiBase:'',searchQuery:'',viewMode:'grid'};
const SHARE_ID_RE=/^[A-Za-z0-9_-]{32,64}$/;
const SHARE_KEY_RE=/^(pw|[A-Za-z0-9_-]{16,256})$/;
const DEFAULT_APP_BASE='https://mypocketdrive.online';

function appBaseUrl(){
 const host=location.hostname.toLowerCase();
 if(host==='mypocketdrive.online'||host==='www.mypocketdrive.online'||host.endsWith('github.io'))return location.origin;
 return DEFAULT_APP_BASE;
}

function appShareHref(target,shareKey=''){
 const params=new URLSearchParams();
 if(SHARE_ID_RE.test(State.shareId||''))params.set('share',State.shareId);
 if(SHARE_KEY_RE.test(shareKey||''))params.set('k',shareKey);
 const q=params.toString();
 return `${appBaseUrl()}/#/${target}${q?'?'+q:''}`;
}
function wireShareAuthLinks(shareKey=''){
 const signIn=document.getElementById('share-signin-link');
 const signUp=document.getElementById('share-signup-link');
 const newLink=document.getElementById('share-new-link');
 const errorSignIn=document.getElementById('share-error-signin-link');
 if(signIn)signIn.href=appShareHref('login',shareKey);
 if(signUp)signUp.href=appShareHref('signup',shareKey);
 if(newLink)newLink.href=appShareHref('signup',shareKey);
 if(errorSignIn)errorSignIn.href=appShareHref('login',shareKey);
 document.querySelectorAll('button.share-sidebar-gate').forEach(el=>{
  el.addEventListener('click',()=>{
   window.location.href=appShareHref('login',shareKey);
  },{once:false});
 });
}
function wireShareSearch(){
 const input=document.getElementById('share-search-input');
 if(!input||input.dataset.bound==='1')return;
 input.dataset.bound='1';
 input.addEventListener('input',()=>{
  State.searchQuery=String(input.value||'').trim().toLowerCase();
  if(State.shareMeta)renderFiles();
 });
}
function wireShareViewToggle(){
 const listBtn=document.getElementById('share-list-view-btn');
 const gridBtn=document.getElementById('share-grid-view-btn');
 if(listBtn&&listBtn.dataset.bound!=='1'){
  listBtn.dataset.bound='1';
  listBtn.addEventListener('click',()=>{
   State.viewMode='list';
   renderFiles();
  });
 }
 if(gridBtn&&gridBtn.dataset.bound!=='1'){
  gridBtn.dataset.bound='1';
  gridBtn.addEventListener('click',()=>{
   State.viewMode='grid';
   renderFiles();
  });
 }
}

async function init(){
 wireShareSearch();
 wireShareViewToggle();
 const FLY_BACKEND='https://mypocketdrive-backend.fly.dev';
 const isStatic=location.hostname.endsWith('github.io')||location.hostname==='mypocketdrive.online';
 if(isStatic){try{const r=await fetch('/api.txt',{cache:'no-store'});if(r.ok){const t=(await r.text()).trim();if(t.startsWith('http'))State.apiBase=t.replace(/\/$/,'')}}catch(e){} if(!State.apiBase)State.apiBase=FLY_BACKEND}else{State.apiBase=location.origin}
 try{document.cookie='ngrok-skip-browser-warning=true; path=/; SameSite=Strict'}catch(e){}
 const pathMatch=location.pathname.match(/\/share\/([A-Za-z0-9_\-]{32,64})/);if(!pathMatch){showError('Invalid link','This URL does not contain a valid share ID.');return}State.shareId=pathMatch[1];
 let fragment=location.hash.replace('#','');if(!fragment){const qp=new URLSearchParams(location.search).get('k');if(qp)fragment=qp}if(fragment){try{const m=JSON.parse(localStorage.getItem('mpd_shared_link_keys')||'{}')||{};m[State.shareId]=fragment;localStorage.setItem('mpd_shared_link_keys',JSON.stringify(m));}catch(_){}}
 wireShareAuthLinks(fragment||'');
 if(getStoredAccessToken()&&fragment){window.location.replace(appShareHref('shared',fragment));return}
 if(!fragment){showError('Incomplete link','The encryption key is missing from this link. Make sure you copied the complete URL.');return}
 if(fragment!=='pw'){try{const rawKeyBuf=b64urlDecode(fragment);if(rawKeyBuf.byteLength!==32)throw new Error('Wrong key length');State.rawShareKey=rawKeyBuf;State.shareKey=await ShareCrypto.importShareKey(rawKeyBuf)}catch(e){showError('Invalid key','The encryption key in this URL is malformed.');return}}
 await loadShareMeta();
}

async function loadShareMeta(){
 try{const headers={'ngrok-skip-browser-warning':'true'};const tok=getStoredAccessToken();if(tok)headers.Authorization=`Bearer ${tok}`;const res=await fetch(`${State.apiBase}/share/${State.shareId}/meta`,{headers});
  if(res.status===401){showError('Sign in required','The owner requires recipients to sign in before opening this shared item.');return}
  if(res.status===403){showError('Access denied','You do not have permission to open this shared item.');return}
  if(res.status===404){showError('Not found','This share link does not exist or has been revoked.');return}
  if(res.status===410){const d=await res.json().catch(()=>({}));showError('This shared item is no longer available',d.detail||'This link expired or reached its download limit.');return}
  if(!res.ok){showError('Error','Could not load share info. Try again.');return}
  State.shareMeta=await res.json();
  if(State.shareMeta.is_password_protected&&!State.shareKey){showPanel('password');return}
  renderFiles();
 }catch(e){showError('Network error','Could not reach server: '+e.message)}
}

async function handlePasswordSubmit(){const pw=document.getElementById('share-password').value.trim();const errEl=document.getElementById('pw-err');const btn=document.getElementById('pw-btn');if(!pw){errEl.textContent='Please enter the password';errEl.classList.remove('hidden');return}errEl.classList.add('hidden');btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Unlocking';try{State.shareKey=await ShareCrypto.deriveShareKeyFromPassword(pw,State.shareMeta.kdf_params);const first=State.shareMeta.wrapped_keys[0];await ShareCrypto.unwrapFileKey(first.wrapped_file_key,first.key_iv,State.shareKey);renderFiles()}catch(e){errEl.textContent='Wrong password or corrupted link';errEl.classList.remove('hidden');btn.disabled=false;btn.textContent='Unlock'}}

function downloadIconSvg(){return '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 20h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'}
function imageIconSvg(){return '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3.5" y="5" width="17" height="14" rx="2.4" stroke="currentColor" stroke-width="1.8"/><path d="m6.7 16 3.6-3.6a1.2 1.2 0 0 1 1.7 0l2.1 2.1.9-.9a1.2 1.2 0 0 1 1.7 0L20 17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="8.7" cy="9" r="1.2" fill="currentColor"/></svg>'}
function createDownloadButton(idx){const button=document.createElement('button');button.className='fr-act-btn share-row-download';button.type='button';button.title='Download';button.setAttribute('aria-label','Download');button.innerHTML=downloadIconSvg();button.addEventListener('click',e=>{e.stopPropagation();downloadSingle(idx)});return button}
function renderFiles(){
  const meta=State.shareMeta;
  const entries=Array.isArray(meta.wrapped_keys)?meta.wrapped_keys:[];
  const single=entries.length===1;
  document.body.classList.toggle('single-share-page',single);
  const panel=document.getElementById('panel-files');
  panel.classList.toggle('single-share',single);
  document.getElementById('share-label').textContent='Shared with me';
  document.getElementById('file-count').textContent=`${entries.length||meta.file_count} file${(entries.length||meta.file_count)!==1?'s':''}`;
  const downloadAllBtn=document.getElementById('download-all-btn');
  if(downloadAllBtn){downloadAllBtn.title=single?'Download':'Download all';downloadAllBtn.setAttribute('aria-label',single?'Download':'Download all')}
  document.getElementById('share-list-view-btn')?.classList.toggle('active-nav',State.viewMode==='list');
  document.getElementById('share-grid-view-btn')?.classList.toggle('active-nav',State.viewMode==='grid');
  const list=document.getElementById('file-list');
  list.replaceChildren();
  list.className=(!single&&State.viewMode==='grid')?'grid-mode':'space-y-0.5';
  const label=document.getElementById('share-files-label');
  if(label){
    label.style.display=single?'none':'';
    label.innerHTML=single?'':`<span>Files</span><span class="count">${entries.length||meta.file_count} file${(entries.length||meta.file_count)!==1?'s':''}</span>`;
  }
  if(single){
    renderSinglePreview(entries[0],list);
    showPanel('files');
    setTimeout(()=>loadSinglePreview(0),30);
    return;
  }
  const q=State.searchQuery;
  const visibleEntries=(q?entries.map((entry,idx)=>({entry,idx})).filter(({entry})=>String(entry.original_name||'File').toLowerCase().includes(q)):entries.map((entry,idx)=>({entry,idx})));
  if(!visibleEntries.length){
    const empty=document.createElement('div');
    empty.className='share-empty-search';
    empty.textContent='No shared files match your search.';
    list.appendChild(empty);
    showPanel('files');
    return;
  }
  visibleEntries.forEach(({entry,idx})=>{
    const row=document.createElement('div');row.className='file-row fade-in';
    row.tabIndex=0;
    row.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();downloadSingle(idx)}});
    if(State.viewMode==='grid'){
      const thumb=document.createElement('div');thumb.className='fr-thumb-wrap';
      const placeholder=document.createElement('span');placeholder.className='thumb-placeholder';placeholder.innerHTML=imageIconSvg();
      thumb.appendChild(placeholder);
      const info=document.createElement('div');info.className='fr-info';
      const name=document.createElement('div');name.className='fr-name';name.textContent=entry.original_name||'File';
      const metaLine=document.createElement('div');metaLine.className='fr-size';metaLine.textContent=`${entry.size?fmtSize(entry.size):''}${entry.size?' - ':''}shared`;
      info.appendChild(name);info.appendChild(metaLine);
      const btnWrap=document.createElement('div');btnWrap.className='fr-acts';btnWrap.id=`file-btn-${idx}`;btnWrap.appendChild(createDownloadButton(idx));
      row.appendChild(thumb);row.appendChild(info);row.appendChild(btnWrap);list.appendChild(row);
      return;
    }
    const icon=document.createElement('span');icon.className='thumb-placeholder';icon.innerHTML=imageIconSvg();
    const name=document.createElement('div');name.className='fr-name';name.textContent=entry.original_name||'File';
    const date=document.createElement('div');date.className='file-date';date.textContent=fmtDate(entry.created_at||entry.updated_at||meta.created_at||'').replace(/,.*$/,'');
    date.className='fr-date';
    const size=document.createElement('div');size.className='fr-size';size.textContent=entry.size?fmtSize(entry.size):'';
    const btnWrap=document.createElement('div');btnWrap.className='fr-acts';btnWrap.id=`file-btn-${idx}`;btnWrap.appendChild(createDownloadButton(idx));
    row.appendChild(icon);row.appendChild(name);row.appendChild(date);row.appendChild(size);row.appendChild(btnWrap);list.appendChild(row);
  });
  showPanel('files');
}

function renderSinglePreview(entry,list){
  const toolbar=document.createElement('div');toolbar.className='share-single-toolbar';
  const topDownload=document.createElement('button');topDownload.type='button';topDownload.className='share-round-download';topDownload.title='Download';topDownload.setAttribute('aria-label','Download file');
  topDownload.innerHTML='<svg viewBox="0 0 24 24" fill="none"><path d="M12 4v10m0 0 4-4m-4 4-4-4M5 20h14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  topDownload.addEventListener('click',()=>downloadSingle(0));
  toolbar.append(topDownload);
  const card=document.createElement('article');card.className='share-preview-card';
  const stage=document.createElement('div');stage.className='share-preview-stage';stage.id='single-preview-stage';
  const icon=document.createElement('div');icon.className='share-preview-icon';icon.textContent=fileIcon(entry.original_name||'');
  const status=document.createElement('div');status.className='share-preview-status';
  const title=document.createElement('h2');title.textContent='Preparing secure preview';
  const copy=document.createElement('p');copy.textContent='The file decrypts locally in this browser.';
  status.appendChild(title);status.appendChild(copy);stage.appendChild(icon);stage.appendChild(status);
  const details=document.createElement('div');details.className='share-preview-details';
  const name=document.createElement('div');name.className='share-preview-name';name.textContent=entry.original_name||'File';
  const meta=document.createElement('div');meta.className='share-preview-meta';meta.textContent=`Viewer${entry.size?' - '+fmtSize(entry.size):''}`;
  const actions=document.createElement('div');actions.className='share-preview-actions';actions.id='file-btn-0';actions.appendChild(createDownloadButton(0));
  details.appendChild(name);details.appendChild(meta);details.appendChild(actions);
  card.appendChild(stage);card.appendChild(details);list.append(toolbar,card);
}

function getEntryMime(entry){
  const name=String(entry.original_name||'').toLowerCase();
  if(entry.mime_type||entry.mime)return String(entry.mime_type||entry.mime).toLowerCase();
  if(/\.(png|jpe?g|gif|webp|bmp|avif|svg)$/.test(name))return 'image/'+name.split('.').pop().replace('jpg','jpeg');
  if(/\.(mp4|webm|ogg|mov|m4v)$/.test(name))return 'video/'+name.split('.').pop();
  if(/\.(mp3|wav|m4a|aac|oga|flac)$/.test(name))return 'audio/'+name.split('.').pop();
  if(name.endsWith('.pdf'))return 'application/pdf';
  if(/\.(txt|md|csv|log|json)$/.test(name))return 'text/plain';
  return 'application/octet-stream';
}

async function fetchSharedNasPreviewBlob(entry){
  const headers={'ngrok-skip-browser-warning':'true','Cache-Control':'no-store'};
  const tok=getStoredAccessToken();if(tok)headers.Authorization=`Bearer ${tok}`;
  const res=await fetch(`${State.apiBase}/share/${State.shareId}/preview/${entry.file_id}`,{headers});
  if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||`HTTP ${res.status}`)}
  return await res.blob();
}
const SHARED_NAS_CHUNK_SIZE=5*1024*1024;
function sharedNasChunkHeaders(downloadId){
  const headers={'ngrok-skip-browser-warning':'true','Cache-Control':'no-store','X-Share-Download-Id':downloadId};
  const tok=getStoredAccessToken();if(tok)headers.Authorization=`Bearer ${tok}`;
  return headers;
}
async function fetchSharedNasChunk(entry,offset,downloadId){
  const url=`${State.apiBase}/share/${State.shareId}/file/${encodeURIComponent(entry.file_id)}/chunk?offset=${offset}`;
  const res=await fetch(url,{headers:sharedNasChunkHeaders(downloadId)});
  if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||`HTTP ${res.status}`)}
  return await res.blob();
}
async function fetchSharedNasDownloadBlob(entry,onProgress){
  const size=Number(entry.size||0);
  if(!size || size<1){
    const chunk=await fetchSharedNasChunk(entry,0,crypto.randomUUID?.()||String(Date.now()));
    onProgress?.(chunk.size||0,chunk.size||0);
    return new Blob([chunk],{type:getEntryMime(entry)});
  }
  const downloadId=crypto.randomUUID?.()||String(Date.now())+Math.random().toString(16).slice(2);
  const chunks=[];
  let loaded=0;
  for(let offset=0;offset<size;offset+=SHARED_NAS_CHUNK_SIZE){
    const chunk=await fetchSharedNasChunk(entry,offset,downloadId);
    chunks.push(chunk);
    loaded+=chunk.size||0;
    onProgress?.(Math.min(loaded,size),size);
  }
  return new Blob(chunks,{type:getEntryMime(entry)});
}
function saveBlobAsFile(blob,filename){
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),60000);
}
async function fetchSharedNasDownloadInfo(entry){
  const headers={'ngrok-skip-browser-warning':'true','Cache-Control':'no-store'};
  const tok=getStoredAccessToken();if(tok)headers.Authorization=`Bearer ${tok}`;
  const res=await fetch(`${State.apiBase}/share/${State.shareId}/file/${encodeURIComponent(entry.file_id)}/download-info`,{headers});
  if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||`HTTP ${res.status}`)}
  return await res.json();
}
async function saveSharedNasDirectTransfer(entry,info,onProgress){
  const filename=info.filename||entry.original_name||'shared-file';
  const size=Number(info.size||entry.size||0);
  const headers=Object.assign({'Cache-Control':'no-store'},info.headers||{});
  let writable=null;
  if(window.showSaveFilePicker){
    const handle=await window.showSaveFilePicker({suggestedName:filename});
    writable=await handle.createWritable();
  }
  let res;
  try{
    res=await fetch(info.download_url,{headers});
    if(!res.ok)throw new Error(`HTTP ${res.status}`);
    if(writable && res.body){
      const reader=res.body.getReader();
      let loaded=0;
      while(true){
        const chunk=await reader.read();
        if(chunk.done)break;
        await writable.write(chunk.value);
        loaded+=chunk.value.byteLength||0;
        onProgress?.(size?Math.min(loaded,size):loaded,size||loaded);
      }
      await writable.close();
      return;
    }
    const blob=await res.blob();
    onProgress?.(blob.size||size,size||blob.size||0);
    if(writable){await writable.write(blob);await writable.close();return;}
    saveBlobAsFile(blob,filename);
  }catch(e){
    if(writable){try{await writable.abort()}catch(_e){}}
    throw e;
  }
}
async function saveSharedNasEntryToDisk(entry,onProgress){
  try{
    const info=await fetchSharedNasDownloadInfo(entry);
    await saveSharedNasDirectTransfer(entry,info,onProgress);
    return;
  }catch(e){
    console.warn('[Pockio Share] direct NAS transfer unavailable; falling back to relay chunks',e);
  }
  const size=Number(entry.size||0);
  const filename=entry.original_name||'shared-file';
  if(!window.showSaveFilePicker || !size || size<1){
    const blob=await fetchSharedNasDownloadBlob(entry,onProgress);
    saveBlobAsFile(blob,filename);
    return;
  }
  const handle=await window.showSaveFilePicker({suggestedName:filename});
  const writable=await handle.createWritable();
  const downloadId=crypto.randomUUID?.()||String(Date.now())+Math.random().toString(16).slice(2);
  let loaded=0;
  try{
    for(let offset=0;offset<size;offset+=SHARED_NAS_CHUNK_SIZE){
      const chunk=await fetchSharedNasChunk(entry,offset,downloadId);
      await writable.write(chunk);
      loaded+=chunk.size||0;
      onProgress?.(Math.min(loaded,size),size);
    }
  }catch(e){
    try{await writable.abort()}catch(_e){}
    throw e;
  }
  await writable.close();
}
function isDirectCloudSharedEntry(entry){return String(entry.storage_version||'').toLowerCase()==='client_e2ee_s3'}
function _stdB64ToBytes(value){
  let raw=String(value||'');
  raw=raw.replace(/-/g,'+').replace(/_/g,'/');
  while(raw.length%4)raw+='=';
  const bin=atob(raw);
  const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);
  return out;
}
function _directCloudPartIv(prefix,partNumber){
  const iv=new Uint8Array(12);
  iv.set(prefix,0);
  new DataView(iv.buffer).setUint32(8,partNumber,false);
  return iv;
}
async function _maybeGunzipSharedBlob(blob,compression,mime){
  if(!compression || compression.alg!=='gzip')return blob;
  if(!('DecompressionStream' in window))throw new Error('This browser cannot decompress this shared cloud file.');
  const stream=blob.stream().pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).blob().then(b=>new Blob([b],{type:mime||blob.type||'application/octet-stream'}));
}
async function _unwrapSharedDirectCloudMaterial(entry,manifest){
  const raw=await ShareCrypto.unwrapFileKey(entry.wrapped_file_key,entry.key_iv,State.shareKey);
  const material=String(entry.key_material||'').toLowerCase();
  if(material==='direct_cloud_wrap_key'){
    const wrapKey=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM',length:256},false,['decrypt']);
    const wrapped=manifest?.wrapped_dek||{};
    if(!wrapped.iv||!wrapped.ciphertext)throw new Error('Encrypted cloud metadata is missing.');
    const rawDek=await crypto.subtle.decrypt({name:'AES-GCM',iv:_stdB64ToBytes(wrapped.iv)},wrapKey,_stdB64ToBytes(wrapped.ciphertext));
    return {rawDek,wrapKey};
  }
  throw new Error('This encrypted cloud share was created before the cloud sharing fix. Create a new share link for this file.');
}
async function _unwrapSharedDirectCloudBlockKey(blockMeta,wrapKey){
  if(!wrapKey || !blockMeta?.wrapped_key?.iv || !blockMeta?.wrapped_key?.ciphertext){
    throw new Error('This shared cloud file was created with older key metadata. Create a new share link for this file.');
  }
  return await crypto.subtle.decrypt({name:'AES-GCM',iv:_stdB64ToBytes(blockMeta.wrapped_key.iv)},wrapKey,_stdB64ToBytes(blockMeta.wrapped_key.ciphertext));
}
async function decryptSharedDirectCloudEntryToBlob(entry){
  const info=await fetchSharedNasDownloadInfo(entry);
  const manifest=info.encryption_manifest||{};
  const {rawDek,wrapKey}=await _unwrapSharedDirectCloudMaterial(entry,manifest);
  const dek=await crypto.subtle.importKey('raw',rawDek,{name:'AES-GCM',length:256},false,['decrypt']);
  if(info.object_layout==='delta')throw new Error('Delta-compressed shared cloud files must be re-shared after this update.');
  const blockEntries=Array.isArray(info.blocks)?info.blocks:null;
  const partSize=Number(manifest.part_size||16*1024*1024);
  const storedPlaintextSize=Number(info.stored_plaintext_size||manifest.stored_plaintext_size||info.plaintext_size||entry.size||0);
  const partCount=Number(manifest.part_count||Math.max(1,Math.ceil(storedPlaintextSize/partSize)));
  const ivPrefix=_stdB64ToBytes(manifest.part_iv_prefix||'');
  const plaintextParts=[];
  let cipherOffset=0;
  for(let partNumber=1;partNumber<=partCount;partNumber++){
    let res,cipherLen,decryptKey=dek,decryptIv=_directCloudPartIv(ivPrefix,partNumber);
    if(blockEntries){
      const block=blockEntries[partNumber-1];
      if(!block?.download_url)throw new Error('Encrypted cloud block URL is missing.');
      const headers={};
      if(block.is_packed&&Number.isFinite(Number(block.range_start))&&Number.isFinite(Number(block.range_end))){
        headers.Range=`bytes=${Number(block.range_start)}-${Number(block.range_end)}`;
      }
      res=await fetch(block.download_url,{headers});
      if(block.is_packed){if(!(res.status===206||res.ok))throw new Error(`Encrypted cloud block download failed: ${res.status}`)}
      else if(!res.ok)throw new Error(`Encrypted cloud block download failed: ${res.status}`);
      const blockMeta=(manifest.blocks||[])[partNumber-1];
      const blockKeyRaw=await _unwrapSharedDirectCloudBlockKey(blockMeta,wrapKey);
      decryptKey=await crypto.subtle.importKey('raw',blockKeyRaw,{name:'AES-GCM'},false,['decrypt']);
      decryptIv=_stdB64ToBytes(blockMeta.iv);
    }else{
      if(!info.download_url)throw new Error('Encrypted cloud download URL is missing.');
      const plainStart=(partNumber-1)*partSize;
      const plainLen=Math.min(partSize,Math.max(0,storedPlaintextSize-plainStart));
      cipherLen=plainLen+16;
      if(partCount===1&&cipherOffset===0)res=await fetch(info.download_url);
      else res=await fetch(info.download_url,{headers:{Range:`bytes=${cipherOffset}-${cipherOffset+cipherLen-1}`}});
      if(!(res.status===206||(partCount===1&&res.ok)))throw new Error(`Encrypted cloud range download failed: ${res.status}`);
    }
    const cipher=await res.arrayBuffer();
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:decryptIv},decryptKey,cipher);
    plaintextParts.push(plain);
    if(!blockEntries)cipherOffset+=cipherLen;
  }
  const mime=info.mime_type||getEntryMime(entry);
  let blob=new Blob(plaintextParts,{type:mime});
  blob=await _maybeGunzipSharedBlob(blob,manifest.compression,mime);
  return blob;
}
async function fetchSharedDownloadBlob(entry){
  if(String(entry.storage_type||'cloud').toLowerCase()==='nas')return await fetchSharedNasDownloadBlob(entry);
  if(isDirectCloudSharedEntry(entry))return await decryptSharedDirectCloudEntryToBlob(entry);
  return await decryptEntryToBlob(entry);
}
function sharePreviewUnavailableHtml(entry){
  return '<div class="share-preview-unavailable"><div class="share-preview-icon">'+fileIcon(entry.original_name||'')+'</div><div class="share-preview-status"><h2>Preview unavailable</h2><p>Please download to view this file.</p></div></div>';
}
async function decryptEntryToBlob(entry){
  if(isDirectCloudSharedEntry(entry))return await decryptSharedDirectCloudEntryToBlob(entry);
  const filename=entry.original_name||'shared-file';
  const headers={'ngrok-skip-browser-warning':'true','Cache-Control':'no-store'};
  const tok=getStoredAccessToken();if(tok)headers.Authorization=`Bearer ${tok}`;
  const res=await fetch(`${State.apiBase}/share/${State.shareId}/file/${entry.file_id}`,{headers});
  if(!res.ok){const d=await res.json().catch(()=>({}));throw new Error(d.detail||`HTTP ${res.status}`)}
  const payload=await res.arrayBuffer();
  const mime=getEntryMime(entry);
  if(String(entry.storage_type||'cloud').toLowerCase()==='nas'){
    return new Blob([payload],{type:mime});
  }
  let fileKeyRaw;
  try{fileKeyRaw=await ShareCrypto.unwrapFileKey(entry.wrapped_file_key,entry.key_iv,State.shareKey)}catch(e){throw new Error(`Key unwrap failed for ${filename}`)}
  let plaintext;
  try{plaintext=await ShareCrypto.decryptBlob(payload,fileKeyRaw)}catch(e){throw new Error(`Decryption failed for ${filename}`)}
  return new Blob([plaintext],{type:mime});
}

const ShareImageZoom={scale:1,x:0,y:0,min:.5,max:5,step:.25,img:null,label:null,stage:null,dragging:false,lastX:0,lastY:0};
function _clampShareZoom(value){return Math.max(ShareImageZoom.min,Math.min(ShareImageZoom.max,value));}
function _applyShareImageZoom(){
  const z=ShareImageZoom;
  if(!z.img)return;
  z.img.style.transform='translate('+z.x+'px,'+z.y+'px) scale('+z.scale+')';
  z.img.style.cursor=z.scale>1?(z.dragging?'grabbing':'grab'):'zoom-in';
  if(z.label)z.label.textContent=Math.round(z.scale*100)+'%';
}
function _setShareImageZoom(scale){
  const z=ShareImageZoom;
  const next=_clampShareZoom(scale);
  if(next<=1){z.x=0;z.y=0;}
  z.scale=next;
  _applyShareImageZoom();
}
function setupShareImageZoom(stage,img){
  stage.replaceChildren();
  stage.classList.add('is-image');
  const wrap=document.createElement('div');
  wrap.className='share-image-wrap';
  const tools=document.createElement('div');
  tools.className='share-zoom-tools';
  const zoomOut=document.createElement('button');zoomOut.type='button';zoomOut.textContent='-';zoomOut.title='Zoom out';
  const zoomLabel=document.createElement('span');zoomLabel.textContent='100%';
  const zoomIn=document.createElement('button');zoomIn.type='button';zoomIn.textContent='+';zoomIn.title='Zoom in';
  const fit=document.createElement('button');fit.type='button';fit.textContent='Fit';fit.title='Reset zoom';
  tools.append(zoomOut,zoomLabel,zoomIn,fit);
  img.classList.add('share-preview-image');
  wrap.appendChild(img);
  stage.append(tools,wrap);
  Object.assign(ShareImageZoom,{scale:1,x:0,y:0,img,label:zoomLabel,stage,dragging:false,lastX:0,lastY:0});
  _applyShareImageZoom();
  zoomOut.addEventListener('click',()=>_setShareImageZoom(ShareImageZoom.scale-ShareImageZoom.step));
  zoomIn.addEventListener('click',()=>_setShareImageZoom(ShareImageZoom.scale+ShareImageZoom.step));
  fit.addEventListener('click',()=>_setShareImageZoom(1));
  img.addEventListener('dblclick',()=>_setShareImageZoom(ShareImageZoom.scale>1?1:2));
  stage.addEventListener('wheel',(event)=>{
    event.preventDefault();
    const delta=event.deltaY<0?ShareImageZoom.step:-ShareImageZoom.step;
    _setShareImageZoom(ShareImageZoom.scale+delta);
  },{passive:false});
  img.addEventListener('pointerdown',(event)=>{
    if(ShareImageZoom.scale<=1)return;
    ShareImageZoom.dragging=true;ShareImageZoom.lastX=event.clientX;ShareImageZoom.lastY=event.clientY;
    img.setPointerCapture?.(event.pointerId);
    _applyShareImageZoom();
  });
  img.addEventListener('pointermove',(event)=>{
    if(!ShareImageZoom.dragging)return;
    ShareImageZoom.x+=event.clientX-ShareImageZoom.lastX;
    ShareImageZoom.y+=event.clientY-ShareImageZoom.lastY;
    ShareImageZoom.lastX=event.clientX;ShareImageZoom.lastY=event.clientY;
    _applyShareImageZoom();
  });
  const stopDrag=(event)=>{ShareImageZoom.dragging=false;try{img.releasePointerCapture?.(event.pointerId);}catch(_e){} _applyShareImageZoom();};
  img.addEventListener('pointerup',stopDrag);
  img.addEventListener('pointercancel',stopDrag);
}
async function loadSinglePreview(idx){
  const entry=State.shareMeta?.wrapped_keys?.[idx];
  const stage=document.getElementById('single-preview-stage');
  if(!entry||!stage)return;
  const mime=getEntryMime(entry);
  const previewable=mime.startsWith('image/')||mime.startsWith('video/')||mime.startsWith('audio/')||mime==='application/pdf'||mime.startsWith('text/');
  if(!previewable){stage.innerHTML=sharePreviewUnavailableHtml(entry);return;}
  try{
    const blob=String(entry.storage_type||'cloud').toLowerCase()==='nas'?await fetchSharedNasPreviewBlob(entry):await decryptEntryToBlob(entry);
    const url=URL.createObjectURL(blob);
    stage.replaceChildren();
    let el;
    if(mime.startsWith('image/')){el=document.createElement('img');el.alt=entry.original_name||'Shared image';el.src=url;setupShareImageZoom(stage,el);return;}
    else if(mime.startsWith('video/')){el=document.createElement('video');el.controls=true;el.playsInline=true;}
    else if(mime.startsWith('audio/')){el=document.createElement('audio');el.controls=true;}
    else if(mime==='application/pdf'){el=document.createElement('iframe');el.title=entry.original_name||'Shared PDF';}
    else{el=document.createElement('pre');el.className='share-text-preview';el.textContent=await blob.text();stage.appendChild(el);setTimeout(()=>URL.revokeObjectURL(url),60000);return;}
    el.src=url;stage.appendChild(el);
  }catch(e){
    stage.innerHTML=sharePreviewUnavailableHtml(entry);
  }
}
function isNasEntry(entry){return String(entry.storage_type||'cloud').toLowerCase()==='nas'}
function isTruthyShareFlag(value){return value===true||value===1||String(value||'').toLowerCase()==='true'||String(value||'')==='1'}
function canUseNativeSharedDownload(entry){return false}
function publicShareApiBase(){
  if(location.hostname==='mypocketdrive.online')return '/api';
  if(location.hostname==='origin-api.mypocketdrive.online')return 'https://api.mypocketdrive.online';
  if(location.hostname.endsWith('github.io'))return State.apiBase;
  return location.origin;
}
function sharedFileUrl(entry){return `${publicShareApiBase()}/share/${State.shareId}/file/${encodeURIComponent(entry.file_id)}`}
function nativeDownloadSharedEntry(entry){
  const url=sharedFileUrl(entry);
  try{
    window.location.assign(url);
  }catch(_){
    const a=document.createElement('a');
    a.href=url;
    a.download=entry.original_name||'shared-file';
    a.rel='noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
}
async function downloadSingle(idx){
  const entry=State.shareMeta.wrapped_keys[idx];
  if(canUseNativeSharedDownload(entry)){
    nativeDownloadSharedEntry(entry);
    toast('Download started','success');
    return;
  }
  const btnEl=document.getElementById(`file-btn-${idx}`);
  if(btnEl){
    btnEl.replaceChildren();
    const sp=document.createElement('span');
    sp.className='spinner';
    btnEl.appendChild(sp);
  }
  try{await decryptAndSave([entry])}catch(e){toast('Download failed: '+e.message,'error')}finally{if(btnEl)btnEl.replaceChildren(createDownloadButton(idx))}
}
async function downloadAll(){
  const entries=State.shareMeta?.wrapped_keys||[];
  const nativeEntries=entries.filter(canUseNativeSharedDownload);
  const browserEntries=entries.filter((entry)=>!canUseNativeSharedDownload(entry));
  if(nativeEntries.length){
    nativeEntries.forEach((entry,i)=>setTimeout(()=>nativeDownloadSharedEntry(entry),i*250));
    toast(nativeEntries.length===1?'Download started':'Downloads started','success');
  }
  if(!browserEntries.length)return;
  const allBtn=document.getElementById('download-all-btn');
  allBtn.disabled=true;
  allBtn.innerHTML='<span class="spinner spinner-sm"></span>';
  try{await decryptAndSave(browserEntries);toast(nativeEntries.length?'Remaining files downloaded':'All files downloaded','success')}catch(e){toast('Download failed: '+e.message,'error')}finally{allBtn.disabled=false;allBtn.innerHTML=downloadIconSvg();allBtn.title=State.shareMeta?.wrapped_keys?.length===1?'Download':'Download all';allBtn.setAttribute('aria-label',allBtn.title);document.getElementById('progress-panel').style.display='none'}
}
async function decryptAndSave(entries){
  const progressPanel=document.getElementById('progress-panel');
  const progressBar=document.getElementById('progress-bar');
  const progressLabel=document.getElementById('progress-label');
  const progressCount=document.getElementById('progress-count');
  const progressDetail=document.getElementById('progress-detail');
  progressPanel.style.display='block';
  const total=entries.length;
  for(let i=0;i<entries.length;i++){
    const entry=entries[i];
    const filename=entry.original_name||`file_${i+1}`;
    progressLabel.textContent=`Decrypting ${filename}`;
    progressCount.textContent=`${i+1} / ${total}`;
    progressBar.style.width=`${Math.round((i/total)*100)}%`;
    progressDetail.textContent=isNasEntry(entry)?'Downloading securely from the shared NAS device.':'Files decrypt locally and are not sent anywhere.';
    if(canUseNativeSharedDownload(entry)){
      progressLabel.textContent=`Starting ${filename}`;
      nativeDownloadSharedEntry(entry);
      progressBar.style.width=`${Math.round(((i+1)/total)*100)}%`;
      continue;
    }
    if(isNasEntry(entry)){
      progressLabel.textContent=`Downloading ${filename}`;
      progressDetail.textContent='Downloading securely from the shared NAS device.';
      await saveSharedNasEntryToDisk(entry,(loaded,size)=>{
        const filePortion=size?loaded/size:1;
        progressBar.style.width=`${Math.round(((i+filePortion)/total)*100)}%`;
      });
    }else{
      const blob=await fetchSharedDownloadBlob(entry);
      saveBlobAsFile(blob,filename);
    }
    progressBar.style.width=`${Math.round(((i+1)/total)*100)}%`;
    if(i<entries.length-1)await new Promise(r=>setTimeout(r,150));
  }
  progressLabel.textContent='All files decrypted and saved';
  progressBar.style.width='100%';
  setTimeout(()=>progressPanel.style.display='none',2600);
}
function bindUi(){document.getElementById('pw-btn')?.addEventListener('click',handlePasswordSubmit);document.getElementById('download-all-btn')?.addEventListener('click',downloadAll);document.getElementById('share-password')?.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();handlePasswordSubmit()}})}
if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',()=>{bindUi();init()})}else{bindUi();init()}






