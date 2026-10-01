const {app,BrowserWindow,Menu,dialog,session,shell}=require('electron');
const https=require('node:https');
const http=require('node:http');
const path=require('node:path');
const {join,dirname}=path;
const {readFileSync,writeFileSync,mkdirSync,existsSync}=require('node:fs');
const {verifyManifest,evaluateRelease,acceptanceRecord}=require('./release-manifest.cjs');

// Public keys pinned inside the application bundle. A manifest signed by
// anything else is not an update, it is untrusted input.
const TRUSTED_RELEASE_KEYS=(()=>{
  try{return JSON.parse(readFileSync(join(__dirname,'release-signing-keys.json'),'utf8')).keys}
  catch{return []}
})();

const DEFAULT_URL='https://incheon-academy-union-os-web.vercel.app';

// The shell's whole same-origin policy is derived from this URL, so an override
// may only relax the transport for a loopback address used by local testing.
// Anything else (plain http to a remote host, file:, embedded credentials, or a
// malformed value) falls back to the shipped production URL rather than silently
// pointing the desktop app at an untrusted or downgraded origin.
function resolveAppUrl(raw){
  if(!raw)return DEFAULT_URL;
  let url;
  try{url=new URL(raw)}catch{return DEFAULT_URL}
  const loopback=url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname);
  if((url.protocol!=='https:'&&!loopback)||url.username||url.password)return DEFAULT_URL;
  return raw.replace(/\/$/,'');
}

const APP_URL=resolveAppUrl(process.env.INCHEON_OS_URL);
const APP_ORIGIN=new URL(APP_URL).origin;
const UPDATE_MANIFEST=`${APP_ORIGIN}/app-release.json`;
const DOWNLOAD_PAGE=`${APP_ORIGIN}/download`;
const PRODUCT_ID='kr.or.incheonacademy.unionos';
const DISPLAY_NAME='실용음악위원회';
const LEGACY_USER_DATA_NAME='실용음악분과 OS';

// Reuse an existing released-shell profile; a display-name change must not
// create an empty cookie jar. Never copy, delete or migrate account data.
const profileCandidates=[LEGACY_USER_DATA_NAME,require('./package.json').name]
  .map(name=>path.join(app.getPath('appData'),name));
const profilePath=profileCandidates.find(directory=>
  existsSync(path.join(directory,'Cookies'))||existsSync(path.join(directory,'Network','Cookies'))
)||profileCandidates.find(directory=>existsSync(directory))||profileCandidates[1];
mkdirSync(profilePath,{recursive:true});
app.setPath('userData',profilePath);
app.setPath('sessionData',profilePath);
// Keep Electron's existing internal package name and keychain identity. Only
// the OS bundle/product/shortcut metadata and visible window title are renamed.

app.setAppUserModelId(PRODUCT_ID);

function sameOrigin(url){
  try{return new URL(url).origin===APP_ORIGIN}catch{return false}
}

function openExternal(url){
  if(/^https?:\/\//i.test(url))void shell.openExternal(url);
}

function fetchJson(url,depth=0){
  return new Promise((resolve,reject)=>{
    if(depth>3){reject(new Error('UPDATE_TOO_MANY_REDIRECTS'));return}
    const parsed=new URL(url);
    const client=parsed.protocol==='http:'?http:https;
    const req=client.get(parsed,{headers:{'user-agent':`IncheonAcademyOS/${app.getVersion()}`}},res=>{
      if((res.statusCode??500)>=300&&(res.statusCode??500)<400&&res.headers.location){
        res.resume();
        // A redirect may not move the manifest fetch off the application
        // origin. The signature would still have to verify, but there is no
        // legitimate reason to follow one and it removes an SSRF-shaped step.
        const next=new URL(res.headers.location,parsed);
        if(next.origin!==APP_ORIGIN){reject(new Error('UPDATE_REDIRECT_OFF_ORIGIN'));return}
        fetchJson(next.toString(),depth+1).then(resolve,reject);
        return;
      }
      if(res.statusCode!==200){res.resume();reject(new Error(`HTTP_${res.statusCode}`));return}
      let body='';
      res.setEncoding('utf8');
      res.on('data',chunk=>{if(body.length<200_000)body+=chunk});
      res.on('end',()=>{try{resolve(JSON.parse(body))}catch(error){reject(error)}});
    });
    req.setTimeout(8_000,()=>req.destroy(new Error('UPDATE_TIMEOUT')));
    req.on('error',reject);
  });
}

// Highest release this installation has already accepted. Persisting it is what
// makes an old but validly signed manifest detectable: a signature stays valid
// forever, so replay is prevented by remembering, not by verifying again.
function acceptanceStatePath(){
  return join(app.getPath('userData'),'release-state.json');
}

// A first run and a damaged state file are different situations. Treating the
// second as the first would silently discard the replay protection, so only a
// genuinely absent file counts as "nothing accepted yet".
function readAcceptanceState(){
  const path=acceptanceStatePath();
  if(!existsSync(path))return{ok:true,state:null};
  try{
    const state=JSON.parse(readFileSync(path,'utf8'));
    if(!state||typeof state!=='object'||Array.isArray(state))return{ok:false,reason:'ACCEPTANCE_STATE_UNREADABLE'};
    return{ok:true,state};
  }catch{return{ok:false,reason:'ACCEPTANCE_STATE_UNREADABLE'}}
}

// If the accepted release cannot be recorded, the next check would accept a
// replay of this same manifest as if it were new. That is reported rather than
// swallowed.
function writeAcceptanceState(record){
  try{
    const path=acceptanceStatePath();
    mkdirSync(dirname(path),{recursive:true});
    writeFileSync(path,JSON.stringify(record));
    return{ok:true};
  }catch{return{ok:false,reason:'ACCEPTANCE_STATE_NOT_PERSISTED'}}
}

/**
 * Update check.
 *
 * The manifest is verified before a single field is read, and every failure
 * path is silent-but-closed: the shell behaves exactly as if there were no
 * update information. It never falls back to the unverified document, and it
 * never tells the user an update exists on the strength of unsigned data.
 */
async function checkForShellUpdate({interactive=false}={}){
  const unavailable=async detail=>{
    if(interactive)await dialog.showMessageBox({type:'warning',title:'업데이트 확인',message:'업데이트 정보를 확인하지 못했습니다.',detail,buttons:['확인']});
  };
  let manifest;
  try{
    manifest=await fetchJson(UPDATE_MANIFEST);
  }catch{
    return unavailable('인터넷 연결을 확인한 뒤 다시 시도해 주세요.');
  }

  // The packaged shell believes production keys only. The reproducible
  // development key is not shipped, and could not be trusted here even if it
  // were: release-manifest.cjs denylists it by value.
  const verified=verifyManifest(manifest,{
    trustedKeys:TRUSTED_RELEASE_KEYS,
    expectedProductId:PRODUCT_ID,
    requireProductionKey:true
  });
  if(!verified.ok){
    // The reason is a fixed identifier, never attacker-supplied manifest text.
    return unavailable(`업데이트 정보의 서명을 확인하지 못해 중단했습니다. (${verified.reason})`);
  }

  const accepted=readAcceptanceState();
  if(!accepted.ok)return unavailable(`이전 업데이트 기록을 읽지 못해 중단했습니다. (${accepted.reason})`);

  const decision=evaluateRelease(verified.release,{
    currentVersion:app.getVersion(),
    lastAccepted:accepted.state
  });
  if(!decision.ok)return unavailable(`업데이트 정보가 유효하지 않아 중단했습니다. (${decision.reason})`);

  const persisted=writeAcceptanceState(acceptanceRecord(verified.release));
  if(!persisted.ok)return unavailable(`업데이트 기록을 저장하지 못해 중단했습니다. (${persisted.reason})`);

  if(!decision.supported){
    await dialog.showMessageBox({
      type:'warning',
      title:'앱 업데이트 필요',
      message:`이 앱 버전은 더 이상 지원되지 않습니다. 최소 지원 버전은 ${verified.release.minimumSupportedVersion}입니다.`,
      detail:'다운로드 페이지에서 최신 설치본을 받아 주세요.',
      buttons:['업데이트 페이지 열기','나중에'],
      defaultId:0,
      cancelId:1
    }).then(result=>{if(result.response===0)openExternal(DOWNLOAD_PAGE)});
    return;
  }

  if(decision.updateAvailable){
    const result=await dialog.showMessageBox({
      type:'info',
      title:'앱 업데이트',
      message:`새 앱 버전 ${verified.release.version}을 사용할 수 있습니다.`,
      detail:'OS 기능과 데이터는 서버에서 자동 갱신됩니다. 앱 이름·아이콘·데스크톱 셸이 바뀌는 경우에만 설치형 앱 업데이트가 필요합니다.',
      buttons:['업데이트 페이지 열기','나중에'],
      defaultId:0,
      cancelId:1
    });
    if(result.response===0)openExternal(DOWNLOAD_PAGE);
    return;
  }
  if(interactive)await dialog.showMessageBox({type:'info',title:'앱 업데이트',message:'현재 최신 앱 버전입니다.',buttons:['확인']});
}

function installMenu(win){
  const template=[
    {
      label:'앱',
      submenu:[
        {label:'OS 새로고침',accelerator:'CmdOrCtrl+R',click:()=>win.webContents.reload()},
        {label:'다운로드 센터',click:()=>win.loadURL(DOWNLOAD_PAGE)},
        {label:'앱 업데이트 확인',click:()=>void checkForShellUpdate({interactive:true})},
        {type:'separator'},
        process.platform==='darwin'?{role:'hide'}:{role:'quit'}
      ]
    },
    {label:'편집',submenu:[{role:'undo'},{role:'redo'},{type:'separator'},{role:'cut'},{role:'copy'},{role:'paste'},{role:'selectAll'}]},
    {label:'보기',submenu:[{role:'resetZoom'},{role:'zoomIn'},{role:'zoomOut'},{type:'separator'},{role:'togglefullscreen'}]}
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createWindow(){
  const win=new BrowserWindow({
    title:DISPLAY_NAME,
    width:1440,
    height:940,
    minWidth:980,
    minHeight:680,
    backgroundColor:'#071b46',
    autoHideMenuBar:process.platform!=='darwin',
    show:false,
    webPreferences:{
      nodeIntegration:false,
      contextIsolation:true,
      sandbox:true,
      webSecurity:true,
      allowRunningInsecureContent:false,
      spellcheck:true
    }
  });

  win.once('ready-to-show',()=>win.show());
  win.webContents.on('render-process-gone',(_event,details)=>{
    if(details.reason!=='clean-exit')void dialog.showMessageBox(win,{type:'warning',title:'앱 화면 복구',message:'앱 화면을 다시 불러옵니다.',buttons:['확인']}).finally(()=>win.reload());
  });

  installMenu(win);
  void win.loadURL(APP_URL);
  return win;
}

// Every renderer must carry the navigation policy, not just the first window.
// A same-origin `window.open` is allowed and produces a new webContents; without
// this the child window kept no guard at all and could then be navigated to any
// remote origin, loading uncontrolled content inside the desktop shell.
function hardenWebContents(contents){
  contents.setWindowOpenHandler(({url})=>{
    if(sameOrigin(url))return{action:'allow'};
    openExternal(url);
    return{action:'deny'};
  });
  contents.on('will-navigate',(event,url)=>{
    if(sameOrigin(url))return;
    event.preventDefault();
    openExternal(url);
  });
  // Subframe navigations (Electron 25+). Older shells simply never emit it.
  contents.on('will-frame-navigate',event=>{
    if(sameOrigin(event.url))return;
    event.preventDefault();
    openExternal(event.url);
  });
  contents.on('will-attach-webview',event=>event.preventDefault());
}

app.on('web-contents-created',(_event,contents)=>hardenWebContents(contents));

app.whenReady().then(()=>{
  session.defaultSession.setPermissionRequestHandler((webContents,permission,callback,details)=>{
    const requestingUrl=details&&details.requestingUrl?details.requestingUrl:webContents.getURL();
    const allowed=sameOrigin(requestingUrl)&&permission==='notifications';
    callback(allowed);
  });
  session.defaultSession.setPermissionCheckHandler((_webContents,permission,requestingOrigin)=>sameOrigin(requestingOrigin)&&permission==='notifications');
  createWindow();
  setTimeout(()=>void checkForShellUpdate(),12_000);
  app.on('activate',()=>{if(BrowserWindow.getAllWindows().length===0)createWindow()});
});

app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit()});
