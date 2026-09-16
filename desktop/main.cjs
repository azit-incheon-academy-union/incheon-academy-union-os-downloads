const {app,BrowserWindow,Menu,dialog,session,shell}=require('electron');
const https=require('node:https');
const http=require('node:http');
const path=require('node:path');
const {existsSync,mkdirSync}=require('node:fs');

const DEFAULT_URL='https://incheon-academy-union-os-web.vercel.app';
const APP_URL=(process.env.INCHEON_OS_URL||DEFAULT_URL).replace(/\/$/,'');
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

function fetchJson(url){
  return new Promise((resolve,reject)=>{
    const parsed=new URL(url);
    const client=parsed.protocol==='http:'?http:https;
    const req=client.get(parsed,{headers:{'user-agent':`IncheonAcademyOS/${app.getVersion()}`}},res=>{
      if((res.statusCode??500)>=300&&(res.statusCode??500)<400&&res.headers.location){
        res.resume();
        fetchJson(new URL(res.headers.location,parsed).toString()).then(resolve,reject);
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

function versionParts(value){
  return String(value||'0').split(/[.-]/).slice(0,3).map(part=>Number.parseInt(part,10)||0);
}

function isNewer(remote,local){
  const a=versionParts(remote);const b=versionParts(local);
  for(let i=0;i<3;i++){if(a[i]>b[i])return true;if(a[i]<b[i])return false}
  return false;
}

async function checkForShellUpdate({interactive=false}={}){
  try{
    const release=await fetchJson(UPDATE_MANIFEST);
    const remote=release&&typeof release.version==='string'?release.version:null;
    if(remote&&isNewer(remote,app.getVersion())){
      const result=await dialog.showMessageBox({
        type:'info',
        title:'앱 업데이트',
        message:`새 앱 버전 ${remote}을 사용할 수 있습니다.`,
        detail:'OS 기능과 데이터는 서버에서 자동 갱신됩니다. 앱 이름·아이콘·데스크톱 셸이 바뀌는 경우에만 설치형 앱 업데이트가 필요합니다.',
        buttons:['업데이트 페이지 열기','나중에'],
        defaultId:0,
        cancelId:1
      });
      if(result.response===0)openExternal(DOWNLOAD_PAGE);
      return;
    }
    if(interactive)await dialog.showMessageBox({type:'info',title:'앱 업데이트',message:'현재 최신 앱 버전입니다.',buttons:['확인']});
  }catch{
    if(interactive)await dialog.showMessageBox({type:'warning',title:'업데이트 확인',message:'업데이트 정보를 확인하지 못했습니다.',detail:'인터넷 연결을 확인한 뒤 다시 시도해 주세요.',buttons:['확인']});
  }
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
  win.webContents.setWindowOpenHandler(({url})=>{
    if(sameOrigin(url))return{action:'allow'};
    openExternal(url);
    return{action:'deny'};
  });
  win.webContents.on('will-navigate',(event,url)=>{
    if(sameOrigin(url))return;
    event.preventDefault();
    openExternal(url);
  });
  win.webContents.on('will-attach-webview',event=>event.preventDefault());
  win.webContents.on('render-process-gone',(_event,details)=>{
    if(details.reason!=='clean-exit')void dialog.showMessageBox(win,{type:'warning',title:'앱 화면 복구',message:'앱 화면을 다시 불러옵니다.',buttons:['확인']}).finally(()=>win.reload());
  });

  installMenu(win);
  void win.loadURL(APP_URL);
  return win;
}

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
