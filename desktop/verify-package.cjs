// Inspect actual packaged OS metadata, retaining exact name/version assertions.
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {createHash}=require('node:crypto');
const pkg=require('./package.json');
const platform=process.argv[2];
const channel=process.argv[3];
const root=path.resolve('dist');
const APP='실용음악위원회';
const ID='kr.or.incheonacademy.unionos';
assert.equal(pkg.build.productName,APP);assert.equal(pkg.build.appId,ID);
const metadata=[];
if(platform==='windows'){
  const unpacked=path.join(root,'win-unpacked');
  const executable=fs.readdirSync(unpacked).find(name=>name===`${APP}.exe`);
  assert.ok(executable,'the unpacked Windows executable must use the new app name');
  const script="[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); $v=(Get-Item -LiteralPath $env:VERIFY_EXE).VersionInfo; @{productName=$v.ProductName;productVersion=$v.ProductVersion} | ConvertTo-Json -Compress";
  const value=JSON.parse(execFileSync('pwsh',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8',env:{...process.env,VERIFY_EXE:path.join(unpacked,executable)}}).trim());
  assert.equal(value.productName,APP);
  // Windows VERSIONINFO uses four numeric components, including revision zero.
  assert.equal(value.productVersion,`${pkg.version}.0`);
  metadata.push({executable,...value});
}else if(platform==='macos'){
  const directories=fs.readdirSync(root,{withFileTypes:true}).filter(entry=>entry.isDirectory()&&entry.name.startsWith('mac')).map(entry=>path.join(root,entry.name));
  for(const directory of directories){
    for(const name of fs.readdirSync(directory).filter(name=>name.endsWith('.app'))){
      // macOS emits decomposed Korean file names; compare canonical equivalents.
      assert.equal(name.normalize('NFC'),`${APP}.app`);
      const plist=path.join(directory,name,'Contents','Info.plist');
      const value=JSON.parse(execFileSync('plutil',['-convert','json','-o','-',plist],{encoding:'utf8'}));
      assert.equal((value.CFBundleDisplayName??value.CFBundleName).normalize('NFC'),APP);
      assert.equal(value.CFBundleName.normalize('NFC'),APP);assert.equal(value.CFBundleIdentifier,ID);
      assert.equal(value.CFBundleShortVersionString,pkg.version);
      metadata.push({app:name,displayName:value.CFBundleDisplayName??value.CFBundleName,appId:value.CFBundleIdentifier,version:value.CFBundleShortVersionString});
    }
  }
  assert.ok(metadata.length,'a packaged macOS app must be inspected');
}else throw new Error('unknown package platform');
const extension=platform==='windows'?'.exe':'.dmg';
const installers=fs.readdirSync(root).filter(name=>name.endsWith(extension));
assert.ok(installers.length,'packaging must produce installers');
const hashes=installers.map(name=>`${createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')}  ${name}`);
const sourceSha=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const report={sourceSha,platform,channel,version:pkg.version,metadata,installers};
fs.writeFileSync(path.join(root,'brand-verification.json'),JSON.stringify(report,null,2)+'\n');
fs.writeFileSync(path.join(root,'SHA256SUMS.txt'),hashes.join('\n')+'\n');
console.log(JSON.stringify(report,null,2));
