'use strict';
// Only the public desktop shell and anonymous HTTPS surfaces are handled here.
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {execFileSync}=require('node:child_process');
const VERSION='1.0.2';
const UPSTREAM='4e60654968ca83402434486ebc0d52753e55798a';
const APP='실용음악위원회';
const ORG='인천학원연합회 음악분과 실용음악위원회';
const BASE='https://incheon-academy-union-os-web.vercel.app';
const blobs={
  'desktop/main.cjs':'08faabf65c666d7d95de10001e36ffeca94739c4',
  'desktop/package.json':'3092a2a7fcca662c91d1a060e4862892df1c5845',
  'desktop/verify-package.cjs':'8855bf38869cc64b22cfa88adb4b23d92a649fa0',
  'desktop/release-manifest.cjs':'8cdd2595f7f58c004a0dea605fd4032145e93714',
  'desktop/code-signature.cjs':'3b16a55b099eb6f9a6639c046b352535c370b073',
  'desktop/release-signing-keys.json':'336dee6bb2868af6ae27ee04195f82c8b2c13ddf',
  'desktop/build/icon.svg':'eb65dbb4dffe031ace689e86c905cc12274fd30f',
  'desktop/build/entitlements.mac.plist':'e1587c7858625377ddcb0039fe55f038e587275f'
};
const names={
  'windows-modern':`Incheon-Academy-OS-Windows-10-11-v${VERSION}-x64.exe`,
  'windows-legacy':`Incheon-Academy-OS-Windows-Legacy-7-8-8.1-v${VERSION}-x64.exe`,
  'macos-modern':`Incheon-Academy-OS-macOS-13-plus-v${VERSION}-universal.dmg`,
  'macos-mojave':`Incheon-Academy-OS-macOS-Mojave-10.14.6-v${VERSION}-x64.dmg`
};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const head=()=>execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const json=file=>JSON.parse(fs.readFileSync(file,'utf8'));
function source(){
  for(const [file,expected] of Object.entries(blobs)){
    const data=fs.readFileSync(file);
    const actual=createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex');
    assert.equal(actual,expected,`upstream source mismatch: ${file}`);
  }
  const pkg=json('desktop/package.json');
  assert.equal(pkg.version,VERSION);assert.equal(pkg.build.productName,APP);
  assert.equal(pkg.build.appId,'kr.or.incheonacademy.unionos');
  const provenance=json('SOURCE-v1.0.2.json');
  assert.equal(provenance.productSourceSha,UPSTREAM);assert.deepEqual(provenance.blobs,blobs);
  console.log('SOURCE_IDENTITY_PASS',UPSTREAM,head());
}
function normalize(platform,channel){
  source();
  const key=`${platform}-${channel}`,target=names[key];
  assert.ok(target,'unsupported release channel');
  const report=json('desktop/dist/brand-verification.json');
  assert.equal(report.sourceSha,head());assert.equal(report.platform,platform);
  assert.equal(report.channel,channel);assert.equal(report.version,VERSION);
  assert.ok(report.metadata.length>0);assert.equal(report.installers.length,1);
  const original=report.installers[0];assert.equal(path.basename(original),original);
  const originalPath=path.join('desktop/dist',original),digest=hash(originalPath);
  const sums=fs.readFileSync('desktop/dist/SHA256SUMS.txt','utf8').trim().split(/\r?\n/);
  assert.deepEqual(sums,[`${digest}  ${original}`]);
  fs.mkdirSync('desktop/release',{recursive:true});
  fs.copyFileSync(originalPath,path.join('desktop/release',target));
  assert.equal(hash(path.join('desktop/release',target)),digest);
  fs.writeFileSync(`desktop/release/${key}-verification.json`,JSON.stringify({...report,productSourceSha:UPSTREAM,publicInstaller:target,installerSha256:digest},null,2)+'\n');
  console.log('NORMALIZED_PACKAGE_PASS',target,digest);
}
function payload(){
  source();
  const expected=Object.entries(names).flatMap(([key,name])=>[name,`${key}-verification.json`]).sort();
  assert.deepEqual(fs.readdirSync('release').sort(),expected,'unexpected/missing release file');
  for(const [key,name] of Object.entries(names)){
    const report=json(`release/${key}-verification.json`);
    assert.equal(report.sourceSha,head());assert.equal(report.productSourceSha,UPSTREAM);
    assert.equal(`${report.platform}-${report.channel}`,key);assert.equal(report.version,VERSION);
    assert.equal(report.publicInstaller,name);assert.equal(report.installerSha256,hash(`release/${name}`));
    assert.ok(report.metadata.length>0);
    for(const item of report.metadata){
      if(report.platform==='windows'){
        assert.equal(item.productName,APP);assert.equal(item.productVersion,`${VERSION}.0`);
      }else{
        assert.equal(item.displayName.normalize('NFC'),APP);assert.equal(item.version,VERSION);
        assert.equal(item.appId,'kr.or.incheonacademy.unionos');
      }
    }
  }
  fs.copyFileSync('SOURCE-v1.0.2.json','release/SOURCE-v1.0.2.json');
  const files=fs.readdirSync('release').sort();
  fs.writeFileSync('release/SHA256SUMS.txt',files.map(name=>`${hash(`release/${name}`)}  ${name}`).join('\n')+'\n');
  console.log('RELEASE_PAYLOAD_PASS',head(),files);
}
async function web(){
  const get=async suffix=>{
    const response=await fetch(BASE+suffix,{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(20000)});
    assert.equal(response.status,200,`public HTTP status: ${suffix}`);return response;
  };
  const login=await (await get('/login')).text();
  assert.match(login,/<title>실용음악위원회<\/title>/);
  assert.ok(login.includes(ORG));
  const manifest=await (await get('/manifest.webmanifest')).json();
  assert.equal(manifest.name,APP);assert.equal(manifest.short_name,APP);
  assert.equal(manifest.start_url,'/login');assert.equal(manifest.scope,'/');
  const download=await (await get('/download')).text();assert.ok(download.includes(APP));
  const health=await (await get('/api/health')).json();assert.equal(health.ok,true);
  const readyResponse=await fetch(BASE+'/api/health/readiness',{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(20000)});
  assert.ok([200,503].includes(readyResponse.status));
  const ready=await readyResponse.json();assert.equal(ready.checks.database,true);assert.equal(ready.checks.objectStorage,true);
  const release=await (await get('/app-release.json')).json();assert.equal(release.displayName,APP);
  fs.mkdirSync('web-evidence',{recursive:true});
  fs.writeFileSync('web-evidence/public-brand-smoke.json',JSON.stringify({checkedAt:new Date().toISOString(),base:BASE,appName:manifest.name,releaseVersion:release.version,health:health.ok,readiness:ready,loginBrand:true,downloadBrand:true},null,2)+'\n');
  console.log('PUBLIC_BRAND_SMOKE_PASS',JSON.stringify({appName:APP,releaseVersion:release.version,checks:ready.checks}));
}
async function main(){
  const command=process.argv[2];
  if(command==='source')source();
  else if(command==='normalize')normalize(process.argv[3],process.argv[4]);
  else if(command==='payload')payload();
  else if(command==='web')await web();
  else throw new Error('unsupported command');
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
