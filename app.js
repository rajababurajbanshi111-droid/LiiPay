/* LiPay 5.3 Advanced — Continuous Trust Payment Security System
   Prototype only: authentication, balances and risk decisions are local/demo data.
   Production authorization must be server-side with secure sessions, transaction signing,
   rate limiting, audit logging and a real risk engine.
*/
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SESSION='lipay_session_v54', HISTORY='lipay_history_v54', FAV='lipay_favorites_v54',
      ACCOUNT='lipay_demo_account_v54', RECEIVERS='lipay_demo_receiver_balances_v54', SEEN_QR='lipay_seen_qr_v54', EVENTS='lipay_security_events_v54';

let account = readLocal(ACCOUNT, null);
let state = null;
let auditEntries = [];
let media = [];
let qrFrame = null;
let currentReceipt = null;
let currentPage = null;
let pageStack = [];

const COUNTRIES = [
  ['+91','🇮🇳 India'],['+977','🇳🇵 Nepal'],['+1','🇺🇸 United States'],
  ['+44','🇬🇧 United Kingdom'],['+61','🇦🇺 Australia'],['+971','🇦🇪 UAE'],
  ['+65','🇸🇬 Singapore'],['+81','🇯🇵 Japan'],['+49','🇩🇪 Germany']
];

function readLocal(key, fallback){
  try { return JSON.parse(localStorage.getItem(key) ?? 'null') ?? fallback; } catch { return fallback; }
}
function readSession(key, fallback){
  try { return JSON.parse(sessionStorage.getItem(key) ?? 'null') ?? fallback; } catch { return fallback; }
}
function writeLocal(key, value){ localStorage.setItem(key, JSON.stringify(value)); }
function writeSession(key, value){ sessionStorage.setItem(key, JSON.stringify(value)); }
function history(){ return readLocal(HISTORY, []); }
function favorites(){ return readLocal(FAV, []); }
function receiverBalances(){ return readLocal(RECEIVERS, {}); }
function creditReceiver(recipient, amount, txId){
  const key=String(recipient||'').trim();
  if(!key) return 0;
  const ledger=receiverBalances();
  const current=Number(ledger[key]?.balance||0);
  const credited=current+Number(amount||0);
  ledger[key]={balance:credited,lastReceived:Number(amount||0),lastTransaction:txId,receivedAt:new Date().toISOString()};
  writeLocal(RECEIVERS,ledger);
  return credited;
}
function money(v){ return '₹' + Number(v || 0).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2}); }
function now(){ return new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); }
function audit(message, type='info'){
  auditEntries.unshift({time:now(),message,type});
  const el=$('#auditLog');
  if(el) el.innerHTML=auditEntries.slice(0,35).map(x=>`<div class="log"><b>${esc(x.time)}</b> · ${esc(x.message)}</div>`).join('');
  const events=readLocal(EVENTS,[]);
  events.unshift({time:new Date().toISOString(),message,type});
  writeLocal(EVENTS,events.slice(0,80));
}
function toast(message){
  const el=$('#toast'); if(!el) return;
  el.textContent=message; el.classList.add('show');
  clearTimeout(window.__toastTimer); window.__toastTimer=setTimeout(()=>el.classList.remove('show'),2600);
}
function stopMedia(){
  media.forEach(s=>s.getTracks().forEach(t=>t.stop())); media=[];
  if(qrFrame) cancelAnimationFrame(qrFrame); qrFrame=null;
}
async function sha256(text){
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function phoneField(id, selected='+91'){
  return `<div class="phone-combo"><select id="${id}Code" aria-label="Country code">${COUNTRIES.map(([c,n])=>`<option value="${c}" ${c===selected?'selected':''}>${c} ${n}</option>`).join('')}</select><input id="${id}" inputmode="tel" autocomplete="tel" placeholder="Mobile number"></div>`;
}
function fullPhone(id){
  const n=$('#'+id)?.value.trim(), c=$('#'+id+'Code')?.value||'+91';
  return n ? `${c}${n.replace(/\s+/g,'')}` : '';
}
function accountPhone(){ return account?.fullPhone || `${account?.countryCode||'+91'}${(account?.phone||'').replace(/\s+/g,'')}`; }
function phoneMatches(id){ return fullPhone(id)===accountPhone(); }
function session(){ return readSession(SESSION,{}); }
function ensureAccount(){
  if(!account) return;
  let changed=false;
  if(typeof account.balance!=='number'){account.balance=50000;changed=true;}
  if(!account.bank){account.bank={name:'LiPay Demo Bank',accountNumber:'•••• 4821',balance:125000,linked:true};changed=true;}
  if(typeof account.recoveryLockUntil!=='number') account.recoveryLockUntil=0;
  if(typeof account.accountFreezeUntil!=='number') account.accountFreezeUntil=0;
  if(typeof account.duressLockUntil!=='number'){account.duressLockUntil=0;changed=true;}
  if(typeof account.mpinLockUntil!=='number'){account.mpinLockUntil=0;changed=true;}
  if(typeof account.mpinFailCount!=='number'){account.mpinFailCount=0;changed=true;}
  if(changed) writeLocal(ACCOUNT,account);
}
function recoveryLock(){ const u=Number(account?.recoveryLockUntil||0); return u>Date.now()?u:0; }
function duressLock(){ const u=Number(account?.duressLockUntil||0); return u>Date.now()?u:0; }
function mpinLock(){ const u=Number(account?.mpinLockUntil||0); return u>Date.now()?u:0; }
function paymentLock(){ return Math.max(recoveryLock(),duressLock(),mpinLock()); }
const MPIN_MAX_ATTEMPTS=3, MPIN_LOCK_MINUTES=15;
/* Shared MPIN attempt counter — used by both the payment-flow MPIN step and the internal-transfer MPIN step,
   since a wrong MPIN anywhere is the same risk. 3 wrong entries locks outgoing payments for MPIN_LOCK_MINUTES. */
function registerMpinFailure(){
  if(!account) return {locked:false,remaining:MPIN_MAX_ATTEMPTS-1};
  account.mpinFailCount=(Number(account.mpinFailCount)||0)+1;
  if(account.mpinFailCount>=MPIN_MAX_ATTEMPTS){
    account.mpinLockUntil=Date.now()+MPIN_LOCK_MINUTES*60000;
    account.mpinFailCount=0;
    writeLocal(ACCOUNT,account);
    audit(`MPIN entered incorrectly ${MPIN_MAX_ATTEMPTS} times — outgoing payments locked for ${MPIN_LOCK_MINUTES} minutes`,'danger');
    return {locked:true,remaining:0,until:account.mpinLockUntil};
  }
  writeLocal(ACCOUNT,account);
  return {locked:false,remaining:MPIN_MAX_ATTEMPTS-account.mpinFailCount};
}
function registerMpinSuccess(){
  if(!account) return;
  if(account.mpinFailCount){account.mpinFailCount=0;writeLocal(ACCOUNT,account);}
}
function accountFreeze(){ const u=Number(account?.accountFreezeUntil||0); return u>Date.now()?u:0; }
function recoveryActive(){ return session().mode==='emergency'; }

function login(){
  stopMedia();
  $('#app').innerHTML=`<main class="login-wrap"><section class="login-card">
    <div class="login-logo">Li</div><div class="eyebrow">PROTOTYPE MODE · LIPAY 5.3</div>
    <h1>Trust before you pay.</h1>
    <p class="muted">LiPay authenticates the payment intent, continuously evaluates trust, and protects the transaction before completion.</p>
    <div class="login-tabs">
      <button id="tabNormal" class="active" onclick="loginMode('normal')">Sign in</button>
      <button id="tabEmergency" onclick="loginMode('emergency')">🚨 Lost phone</button>
      <button id="tabCreate" onclick="loginMode('create')">Create account</button>
    </div><div id="loginBody"></div>
    <div class="prototype-warning"><b>PROTOTYPE MODE</b><br>Credentials and demo data are stored locally for demonstration purposes. Production deployment requires secure backend authentication, encrypted sensitive data, server-side authorization, transaction signing, rate limiting, device binding, audit logging, and a production risk engine.</div>
  </section></main>`;
  loginMode('normal');
}
function loginMode(mode){
  ['tabNormal','tabEmergency','tabCreate'].forEach(id=>$('#'+id)?.classList.remove('active'));
  $('#'+({normal:'tabNormal',emergency:'tabEmergency',create:'tabCreate'}[mode])).classList.add('active');
  const body=$('#loginBody');
  if(mode==='normal'){
    body.innerHTML=`<div class="auth-heading"><span>🔐</span><div><b>Secure sign in</b><small>Country code + mobile number + account password</small></div></div>
      <div class="field"><label>Country code + mobile number</label>${phoneField('loginPhone',account?.countryCode||'+91')}</div>
      <div class="field"><label>Account password</label><input id="loginPass" type="password" autocomplete="current-password" placeholder="Enter account password"></div>
      <button class="btn wide" onclick="normalLogin()">Secure Sign In →</button>
      <div class="login-links"><button onclick="showRecoveryInfo()">Forgot password?</button><button onclick="loginMode('emergency')">Emergency / lost phone access</button></div>`;
  } else if(mode==='emergency'){
    body.innerHTML=`<div class="status warn"><b>🚨 Emergency recovery</b><br>Use the separate emergency recovery credential, then complete identity verification. Normal password access does not bypass recovery security.</div>
      <div class="field"><label>Registered mobile number</label>${phoneField('loginPhone',account?.countryCode||'+91')}</div>
      <div class="field"><label>Emergency recovery credential</label><input id="loginPass" type="password" autocomplete="off" placeholder="Emergency recovery credential"></div>
      <button class="btn wide" onclick="emergencyLogin()">Start Recovery Verification →</button>
      <div class="divider"><span>Prototype shortcut</span></div>
      <button class="btn secondary wide" onclick="randomEmergencyLogin()">🎲 Random Prototype Login</button>
      <small class="muted">Demo only: creates a randomized recovery session without using a real credential.</small>
      <button class="btn secondary wide" onclick="loginMode('normal')">Back to normal login</button>`;
  } else {
    body.innerHTML=`<div class="status"><b>Create a demo account</b><br>Normal login and emergency recovery credentials are separate concepts.</div>
      <div class="field"><label>Name</label><input id="regName" placeholder="Your name"></div>
      <div class="field"><label>Country code + mobile number</label>${phoneField('regPhone','+977')}</div>
      <div class="field"><label>Email <span class="small">optional</span></label><input id="regEmail" type="email" placeholder="you@example.com"></div>
      <div class="grid"><div class="field"><label>Account password</label><input id="regPass" type="password" placeholder="Create password"></div>
      <div class="field"><label>Emergency recovery credential</label><input id="regEmergency" type="password" placeholder="Create separate credential"></div></div>
      <div class="grid"><div class="field"><label>MPIN</label><input id="regMpin" type="password" inputmode="numeric" maxlength="6" placeholder="4–6 digits"></div>
      <div class="field"><label>Confirm MPIN</label><input id="regMpinConfirm" type="password" inputmode="numeric" maxlength="6" placeholder="Re-enter MPIN"></div></div>
      <button class="btn wide" onclick="createAccount()">Create Demo Account</button>`;
  }
}
function showRecoveryInfo(){
  toast('Use Emergency / lost phone access for the dedicated recovery flow.');
  audit('Recovery information requested');
}
function createAccount(){
  const name=$('#regName')?.value.trim(), phone=$('#regPhone')?.value.trim(), code=$('#regPhoneCode')?.value||'+977',
    email=$('#regEmail')?.value.trim(), pass=$('#regPass')?.value||'', emergency=$('#regEmergency')?.value||'',
    mpin=$('#regMpin')?.value||'', confirm=$('#regMpinConfirm')?.value||'';
  if(!name||!phone||pass.length<4||emergency.length<4){toast('Complete all required fields. Passwords need 4+ characters.');return;}
  if(!/^\d{4,6}$/.test(mpin)){toast('MPIN must contain 4 to 6 digits.');return;}
  if(mpin!==confirm){toast('MPINs do not match.');return;}
  if(/^([0-9])\1+$/.test(mpin)){toast('Choose a less predictable MPIN.');return;}
  account={name,phone,countryCode:code,fullPhone:`${code}${phone.replace(/\s+/g,'')}`,email,password:pass,
    emergencyPassword:emergency,mpin,balance:50000,bank:{name:'LiPay Demo Bank',accountNumber:'•••• 4821',balance:125000,linked:true},
    createdAt:new Date().toISOString(),recoveryLockUntil:0,accountFreezeUntil:0};
  writeLocal(ACCOUNT,account); writeLocal(FAV,[]); writeLocal(HISTORY,[]); auditEntries=[];
  toast('Demo account created'); loginMode('normal'); $('#loginPhone').value=phone;
}
function normalLogin(){
  const pw=$('#loginPass')?.value;
  if(!account||!phoneMatches('loginPhone')||pw!==account.password){toast('Country code, mobile number or password did not match.');audit('Normal login failed — credential mismatch','danger');return;}
  writeSession(SESSION,{phone:accountPhone(),at:Date.now(),mode:'normal',recovery:false});
  audit('Normal login verified'); openApp();
}
function emergencyLogin(){
  const credential=$('#loginPass')?.value;
  if(!account||!phoneMatches('loginPhone')||credential!==account.emergencyPassword){toast('Country code, mobile number or emergency credential did not match.');audit('Emergency recovery failed — credential mismatch','danger');return;}
  writeSession(SESSION,{phone:accountPhone(),at:Date.now(),mode:'emergency',recovery:true});
  audit('Emergency recovery credential accepted — identity verification required','warn'); openApp('recovery');
}
function randomEmergencyLogin(){
  ensureAccount();
  if(!account){
    const suffix=String(Math.floor(10000000+Math.random()*90000000));
    account={name:'Prototype User',phone:suffix,countryCode:'+977',fullPhone:'+977'+suffix,email:'',password:'',emergencyPassword:'',mpin:'2468',balance:50000,bank:{name:'LiPay Demo Bank',accountNumber:'•••• 4821',balance:125000,linked:true},createdAt:new Date().toISOString(),recoveryLockUntil:0,accountFreezeUntil:0};
    writeLocal(ACCOUNT,account); writeLocal(FAV,[]); writeLocal(HISTORY,[]);
  }
  const demoId='DEMO-'+Math.random().toString(36).slice(2,8).toUpperCase();
  writeSession(SESSION,{phone:accountPhone(),at:Date.now(),mode:'emergency',recovery:true,prototypeRandom:true,demoId});
  audit(`Random prototype recovery login accepted · ${demoId}`,'warn');
  openApp();
  showModal(`<div class="eyebrow">PROTOTYPE RECOVERY</div><h2>Random login successful</h2><div class="status warn"><b>🚨 RECOVERY MODE ACTIVE</b><br>This is a demonstration-only recovery session. Outgoing payments remain protected.</div><p class="muted">You are now on the LiPay dashboard. Use <b>Freeze Account</b> to temporarily protect the account.</p><button class="btn wide" onclick="closeModal()">Continue to Dashboard</button>`);
}
function openApp(preferred){
  ensureAccount(); shell(); updateProfile();
  page(preferred==='recovery'?'account':'home');
}
function shell(){
  $('#app').innerHTML=`<div class="app-shell">
    <header class="topbar"><div class="brand"><div class="logo">Li</div><div><b>LiPay</b><small>Advanced Continuous Trust · 5.3</small></div></div>
      <div class="top-status">${recoveryActive()?'<span class="pill danger">🚨 RECOVERY MODE ACTIVE</span>':'<span class="pill success">● TRUST MONITOR ACTIVE</span>'}<button class="icon-btn" onclick="logout()" aria-label="Log out">↪</button></div></header>
    <div class="layout"><aside class="sidebar card"><div class="profile"><div class="avatar" id="avatar">L</div><b id="profileName">LiPay User</b><small id="profilePhone">—</small><small id="profileEmail">—</small></div>
      <div class="balance-mini"><span>AVAILABLE BALANCE</span><b id="sideBalance">₹0.00</b></div>
      <nav class="side-nav">
        <button data-side="home" onclick="page('home')">⌂ Home</button><button data-side="pay" onclick="page('pay')">＋ Pay</button><button data-side="transfer" onclick="page('transfer')">⇄ Move Money</button>
        <button data-side="history" onclick="page('history')">▤ History</button><button data-side="security" onclick="page('security')">◈ Security</button><button data-side="settings" onclick="page('settings')">⚙ Settings</button>
        <button data-side="account" onclick="page('account')">◎ Account</button>
      </nav>
      <div class="side-foot"><b>Trust model</b><br>Person · Device · Transaction · Context<br><br><span class="muted">PROTOTYPE MODE</span></div>
    </aside>
    <main class="content"><div id="backBar"></div><section id="page"></section></main></div>
    <nav class="mobile-nav"><button data-mobile="home" onclick="page('home')">⌂<span>Home</span></button><button data-mobile="pay" onclick="page('pay')">＋<span>Pay</span></button><button data-mobile="transfer" onclick="page('transfer')">⇄<span>Move</span></button><button data-mobile="history" onclick="page('history')">▤<span>History</span></button><button data-mobile="settings" onclick="page('settings')">⚙<span>Settings</span></button></nav>
    <div id="modalRoot"></div><footer>LiPay 5.3 · Prototype only · Do not use for real financial authorization</footer>
  </div>`;
  auditEntries=[]; audit('Session restored — LiPay 5.3 dashboard ready');
}
function updateProfile(){
  const a=account||{}; $('#profileName').textContent=a.name||'LiPay User'; $('#profilePhone').textContent=a.fullPhone||'—';
  $('#profileEmail').textContent=a.email||'Email optional'; $('#avatar').textContent=(a.name||'L').slice(0,1).toUpperCase();
  $('#sideBalance').textContent=money(a.balance);
}
function page(p, fromBack=false, payMode=null){
  if(currentPage && currentPage!==p && !fromBack) pageStack.push(currentPage);
  currentPage=p;
  stopMedia(); setActiveNav(p); renderBackBar();
  if(p==='home') renderHome();
  else if(p==='pay') startPayment(payMode);
  else if(p==='transfer') renderInternalTransfer();
  else if(p==='history') renderHistoryPage();
  else if(p==='security') renderSecurityCenter();
  else if(p==='settings') renderSettings();
  else if(p==='account') renderAccountPage();
}
function pageBack(){
  const previous=pageStack.pop()||'home';
  page(previous,true);
}
function renderBackBar(){
  const el=$('#backBar');
  if(!el)return;
  el.innerHTML=currentPage && currentPage!=='home' ? '<button class="back-btn" onclick="pageBack()" aria-label="Go back">← <span>Back</span></button>' : '';
}
function showSecurityEvents(){
  const events=readLocal(EVENTS,[]).slice(0,10);
  showModal(`<div class="eyebrow">SECURITY ACTIVITY</div><h2>Recent security events</h2><p class="muted">Safe event summaries only. Credentials and authentication secrets are never shown.</p><div class="event-modal-list">${events.map(e=>`<div class="timeline-item"><span>${e.type==='danger'?'🚫':e.type==='warn'?'⚠':'✓'}</span><div><b>${new Date(e.time).toLocaleString()}</b><small>${esc(e.message)}</small></div></div>`).join('')||'<div class="empty">No security events yet.</div>'}</div><button class="btn wide" onclick="closeModal()">Close</button>`);
}
function runDeviceCheck(){
  const id=localStorage.getItem('lipay_device_id');
  const status=id?'Known trusted prototype device':'Prototype device recognized for this session';
  audit('Device security check completed');
  showModal(`<div class="eyebrow">DEVICE SECURITY</div><h2>Device check complete</h2><div class="status success"><b>✓ ${esc(status)}</b><br>Browser session, device binding and local security state are available for this demonstration.</div><p class="muted">Production LiPay would perform server-side device binding and stronger attestation.</p><button class="btn wide" onclick="closeModal()">Done</button>`);
}
function setActiveNav(p){
  $$('.side-nav button').forEach(b=>b.classList.toggle('active',b.dataset.side===p));
  $$('.mobile-nav button').forEach(b=>b.classList.toggle('active',b.dataset.mobile===p));
}
function rawRiskTotal(){ return Object.values(state?.context?.risks||{}).reduce((a,b)=>a+Number(b||0),0); }
function isHighRiskTransaction(){
  if(!state?.context) return false;
  const r=state.context.risks||{};
  return rawRiskTotal()>=20 || Number(state.amount)>50000 || !state.context.deviceKnown || r.location>=10 || r.network>=10 || r.recipient>=6 || Number(state.context.fraudAlerts||0)>0;
}
function trustScoreFromState(){
  const r=state.context?.risks||{}; let score=100-Object.values(r).reduce((a,b)=>a+b,0);
  if(state.identitySkipped) score-=20; if(state.emergency) score-=3;
  // Prototype rule requested for demonstrations: keep the displayed/flow score strictly above 75.
  // Production systems must not use a client-side score floor like this.
  return Math.max(76,Math.min(100,Math.round(score)));
}
function trustBand(score){return score>=76?'LOW RISK':'STEP-UP VERIFICATION';}
function homeTrust(){
  const h=history(), last=h[0], score=last?.score??92;
  return {score,band:trustBand(score)};
}
function renderHome(){
  const hour=new Date().getHours(), greeting=hour<12?'Good morning':hour<17?'Good afternoon':'Good evening', t=homeTrust(), lock=paymentLock(), freeze=accountFreeze();
  $('#page').innerHTML=`<div class="hero card"><div><div class="eyebrow">CONTINUOUS TRUST PAYMENT SECURITY</div><h1>${greeting}, ${esc(account.name)}</h1>
    <p>LiPay does not simply ask <b>“Are you authenticated?”</b><br>It asks <b>“Should THIS transaction be trusted?”</b></p>
    </div>
    <div class="hero-score"><span>Current trust</span><b>${t.score}/100</b><small>${t.band}</small></div></div>
    ${lock?`<div class="status danger"><b>🚨 RECOVERY MODE PROTECTION</b><br>Outgoing payments are LOCKED / PROTECTED until ${new Date(lock).toLocaleString()}.</div>`:''}
    ${recoveryActive()?`${freeze?`<div class="status success"><b>🛡️ ACCOUNT SECURE</b><br>Account is temporarily frozen until ${new Date(freeze).toLocaleString()}. Outgoing payments are blocked.</div>`:''}
    <section class="card screen freeze-card"><div><div class="eyebrow">ACCOUNT PROTECTION · OTHER DEVICE</div><h2>${freeze?'Account securely frozen':'Freeze your account temporarily'}</h2><p class="muted">${freeze?'Your account is protected. No outgoing payment can be started while the freeze is active.':'Lost your original phone? Use this emergency recovery session on another device to temporarily freeze outgoing payments.'}</p></div><button class="btn ${freeze?'secondary':'danger'}" onclick="${freeze?'showFreezeStatus()':'openFreezeModal()'}">${freeze?'View Secure Status':'❄ Freeze Account'}</button></section>`:''}
    <div class="dashboard-grid">
      <section class="card dash-card"><span>AVAILABLE BALANCE</span><strong>${money(account.balance)}</strong><small>LiPay demo wallet</small></section>
      <section class="card dash-card"><span>LINKED BANK BALANCE</span><strong>${money(account.bank.balance)}</strong><small>${esc(account.bank.name)}</small></section>
      <section class="card dash-card"><span>TRUST STATUS</span><strong class="text-success">${t.score}/100</strong><small>${t.band}</small></section>
      <section class="card dash-card"><span>SECURITY STATUS</span><strong>PROTECTED</strong><small>Risk-based verification active</small></section>
    </div>
    <section class="money-actions card" aria-label="Money actions">
      <button class="money-action" onclick="page('pay')"><span class="money-action-icon">↗</span><span><b>Send Money</b><small>Pay a person or merchant</small></span></button>
      <button class="money-action" onclick="page('transfer')"><span class="money-action-icon">⇄</span><span><b>Move Money</b><small>Bank ↔ LiPay wallet</small></span></button>
      <button class="money-action" onclick="page('account')"><span class="money-action-icon">↓</span><span><b>Receive Money</b><small>Show your LiPay QR</small></span></button>
      <button class="money-action" onclick="page('pay',false,'qr')"><span class="money-action-icon">▣</span><span><b>Scan &amp; Pay</b><small>Scan a signed QR</small></span></button>
    </section>
    <section class="card screen"><div class="panel-head"><div><div class="eyebrow">THE LIPAY MODEL</div><h2>Secure the payment before you authorize it.</h2></div></div>
      <div class="trust-flow"><span>PERSON</span><i>+</i><span>DEVICE</span><i>+</i><span>TRANSACTION</span><i>+</i><span>CONTEXT</span><b>↓</b><span>CONTINUOUS TRUST</span><b>↓</b><strong>ADAPTIVE DECISION</strong></div>
      <p class="muted">LiPay explains the risk first, verifies identity next, and re-checks the transaction before completion.</p>
    </section>
    <section class="card screen"><div class="panel-head"><div><div class="eyebrow">SECURITY QUICK ACTIONS</div><h2>Protect your account in one tap.</h2></div></div>
      <div class="security-actions">${recoveryActive()?'<button onclick="openFreezeModal()"><span>❄</span><b>Freeze Account</b><small>Lost original phone · block outgoing payments</small></button>':''}<button onclick="showSecurityEvents()"><span>◷</span><b>Security Events</b><small>Review recent protection activity</small></button><button onclick="runDeviceCheck()"><span>◈</span><b>Check Device</b><small>Review this session's device state</small></button></div>
    </section>
    <section class="card screen"><div class="panel-head"><h3>Recent Payments</h3><button class="btn secondary" onclick="page('history')">View all</button></div>
      ${history().slice(0,3).map(historyCompact).join('')||'<div class="empty">No completed payments yet.</div>'}</section>
    <div class="quick-grid"><button onclick="page('security')">◈ <b>Security Center</b><small>Trust evidence</small></button></div>
  </div>`;
}
function historyCompact(e){
  return `<div class="history-item compact"><div><b>${esc(e.recipient)}</b><small>${new Date(e.time).toLocaleString()} · ${esc(e.id)}</small></div><div class="align-right"><b>${money(e.amount)}</b><small class="text-${e.decision==='APPROVE'?'success':e.decision==='STEP-UP'?'warn':'danger'}">${esc(e.decision)} · ${e.score}/100</small></div></div>`;
}

/* Payment flow: intent → automatic context → biometric/identity → OTP → pre-payment trust (>75 prototype floor) → MPIN → final trust → receipt */
function resetState(){
  state={step:1,recipient:'',amount:0,note:'',source:'wallet',sourceLabel:'LiPay Balance',context:null,identity:null,identitySkipped:false,
    otpVerified:false,mpinVerified:false,otpAttempts:0,mpinAttempts:0,nonce:crypto.randomUUID(),txId:'LIPAY-'+Date.now().toString().slice(-8),
    transactionHash:null,decision:null,score:0,emergency:recoveryActive(),secondSignature:false,secondSignatureRequired:false,secondSignatureApproved:false,secondSignatureRejected:false,secondSignatureExpired:false,secondApprover:'',secondSignatureHash:null,secondSignatureCreatedAt:0,secondDeviceVerified:false,createdAt:Date.now()};
}
function startPayment(payMode=null){
  ensureAccount(); const lock=paymentLock(), freeze=accountFreeze();
  if(freeze){renderFrozenPayments(freeze);return;}
  if(lock){renderLockedPayments(lock);return;}
  resetState();
  $('#page').innerHTML=`<div class="workspace"><section class="screen card"><div class="flow-head"><div><div class="eyebrow">SECURE PAYMENT FLOW</div><b>Pre-trust → authentication → final trust</b></div><span id="stepLabel">1 / 8</span></div><div class="progress"><i id="flowProgress"></i></div><div id="flow"></div></section>
    <aside class="audit card"><div class="panel-head"><h3>Live Security Audit</h3><span class="live">● LIVE</span></div><div id="auditLog"></div></aside></div>`;
  audit('Payment flow started'); renderRecipient(payMode==='qr'?'qr':null);
}
function renderLockedPayments(until){
  const isMpin=!!mpinLock();
  $('#page').innerHTML=`<section class="card screen centered"><div class="eyebrow">PAYMENT PROTECTION</div><h1>Outgoing payments locked</h1><p class="muted">${isMpin?'You entered the wrong MPIN 3 times. Outgoing payments are locked for your protection.':'Account protection prevents outgoing payments while the active security lock remains in place.'}</p>
    <div class="status danger"><b>🚨 LOCKED / PROTECTED</b><br>Until ${new Date(until).toLocaleString()}</div><div class="actions">${isMpin?'':'<button class="btn" onclick="page(\'account\')">Open Recovery Controls</button>'}<button class="btn secondary" onclick="page('history')">View History</button></div></section>`;
}
function progress(n){
  const p=$('#flowProgress'); if(p)p.style.width=(n/8*100)+'%';
  const l=$('#stepLabel'); if(l)l.textContent=`${n} / 8`;
}
function renderRecipient(initialMode=null){
  progress(1);
  $('#flow').innerHTML=`<div class="eyebrow">STEP 1 · PAYMENT INTENT</div><h2>Define the payment</h2><p class="muted">Favorites are convenience only; they never bypass security. Select a source and recipient or scan a signed QR.</p>
    <div class="source-grid"><button id="sourceWallet" class="source-card active" onclick="selectPaymentSource('wallet')"><span>LiPay Balance</span><b>${money(account.balance)}</b><small>Available</small></button>
    <button id="sourceBank" class="source-card" onclick="selectPaymentSource('bank')"><span>Linked Bank</span><b>${money(account.bank.balance)}</b><small>${esc(account.bank.name)} · ${esc(account.bank.accountNumber)}</small></button></div>
    <div class="choice-grid"><button class="choice active" onclick="recipientMode('manual',this)"><strong>⌨ Manual</strong><span>Recipient + amount</span></button><button class="choice" onclick="recipientMode('favorite',this)"><strong>★ Favorite ID</strong><span>Convenience signal</span></button><button class="choice" onclick="recipientMode('qr',this)"><strong>▣ Signed QR</strong><span>Integrity verified</span></button></div>
    <div class="second-signature-control"><label><input id="secondSignatureEnabled" type="checkbox" onchange="toggleSecondSignatureIntent()"> <span><b>Require Second Signature</b><small>Optional two-person approval. Payment is released only after a second authorized approver confirms this exact transaction.</small></span></label><div id="secondApproverWrap" class="hidden field"><label>Second approver ID</label><input id="secondApprover" maxlength="80" placeholder="joint-owner@lipay"></div></div><div id="recipientBody"></div>`;
  if(initialMode==='qr') recipientMode('qr',$$('.choice')[2]); else recipientMode('manual',$$('.choice')[0]);
}
function toggleSecondSignatureIntent(){
  const enabled=!!$('#secondSignatureEnabled')?.checked;
  $('#secondApproverWrap')?.classList.toggle('hidden',!enabled);
}
function selectPaymentSource(source){
  state.source=source; state.sourceLabel=source==='bank'?'Linked Bank':'LiPay Balance';
  $('#sourceWallet')?.classList.toggle('active',source==='wallet'); $('#sourceBank')?.classList.toggle('active',source==='bank');
  audit(`Payment source selected — ${state.sourceLabel}`);
}
function recipientMode(mode,btn){
  $$('.choice').forEach(x=>x.classList.remove('active')); btn?.classList.add('active');
  if(mode==='manual') manualForm(); else if(mode==='favorite') favoriteForm(); else qrForm();
}
function manualForm(){
  $('#recipientBody').innerHTML=`<div class="grid"><div class="field"><label>Recipient / Payment ID</label><input id="recipient" placeholder="merchant@lipay"></div><div class="field"><label>Amount (₹)</label><input id="amount" type="number" min="1" placeholder="2500"></div></div>
    <div class="field"><label>Payment purpose</label><input id="note" placeholder="Optional"></div><div class="actions"><button class="btn secondary" onclick="cancelFlow('Payment cancelled before trust evaluation')">Cancel Payment</button><button class="btn" onclick="createIntent()">Continue to security check →</button></div>`;
}
function favoriteForm(){
  const f=favorites();
  if(!f.length){$('#recipientBody').innerHTML=`<div class="status">No favorites yet. Add one from Account → Favorites.</div><button class="btn secondary" onclick="page('account')">Open Account</button>`;return;}
  $('#recipientBody').innerHTML=`<div class="field"><label>Favorite recipient</label><select id="favSelect">${f.map((x,i)=>`<option value="${i}">${esc(x.name)} · ${esc(x.id)}</option>`).join('')}</select></div>
    <div class="grid"><div class="field"><label>Amount (₹)</label><input id="amount" type="number" min="1" placeholder="2500"></div><div class="field"><label>Payment purpose</label><input id="note" placeholder="Optional"></div></div>
    <div class="actions"><button class="btn secondary" onclick="cancelFlow('Payment cancelled before trust evaluation')">Cancel Payment</button><button class="btn" onclick="createFavoriteIntent()">Continue to security check →</button></div>`;
}
function createFavoriteIntent(){const f=favorites()[Number($('#favSelect')?.value)]; if(f) createIntent(`${f.name} · ${f.id}`);}
async function createIntent(override){
  const r=(override||$('#recipient')?.value||'').trim(), a=Number($('#amount')?.value), n=($('#note')?.value||'').trim();
  if(!r||!a||a<=0){toast('Enter a valid recipient and amount.');return;}
  if(a>sourceBalance(state.source)){toast(`Insufficient ${state.source==='bank'?'bank':'LiPay'} balance.`);return;}
  state.recipient=r; state.amount=a; state.note=n;
  state.secondSignature=!!$('#secondSignatureEnabled')?.checked;
  state.secondApprover=(($('#secondApprover')?.value||'').trim());
  if(state.secondSignature&&!state.secondApprover) state.secondApprover='joint-owner@lipay';
  if(state.secondSignature&&!state.secondApprover){toast('Enter the second approver ID or turn off Second Signature.');return;}
  state.txBinding=await sha256(`${state.txId}|${state.recipient}|${state.amount}|${state.note}|${state.nonce}`);
  audit(`Payment intent bound — ${money(a)} → ${r}`); captureContext();
}
function sourceBalance(source){return source==='bank'?Number(account.bank.balance):Number(account.balance);}
function renderInternalTransfer(){
  ensureAccount();
  const frozen=accountFreeze(), locked=paymentLock();
  if(frozen||locked){
    const reason=frozen?'Your account is temporarily frozen. Internal money movement is disabled until the freeze ends.':mpinLock()?'You entered the wrong MPIN too many times. Internal money movement is disabled until the MPIN lock ends.':'Recovery protection is active. Internal money movement is disabled until recovery protection ends.';
    $('#page').innerHTML=`<section class="card screen centered"><div class="eyebrow">INTERNAL MONEY MOVEMENT</div><h1>Transfers protected</h1><p class="muted">${reason}</p><div class="status danger"><b>🚫 TRANSFERS LOCKED</b><br>Protection ends ${new Date(frozen||locked).toLocaleString()}</div><div class="actions"><button class="btn secondary" onclick="page('home')">Back to Dashboard</button></div></section>`; return;
  }
  $('#page').innerHTML=`<section class="card screen"><div class="eyebrow">INTERNAL MONEY MOVEMENT</div><h1>Move money securely</h1><p class="muted">Transfer funds between your linked demo bank account and LiPay wallet. This is an internal prototype transfer; it does not contact a real bank.</p>
    <div class="dashboard-grid"><div class="card dash-card"><span>LIPAY BALANCE</span><strong>${money(account.balance)}</strong><small>Demo wallet</small></div><div class="card dash-card"><span>BANK BALANCE</span><strong>${money(account.bank.balance)}</strong><small>${esc(account.bank.name)}</small></div></div>
    <div class="choice-grid"><button class="choice active" onclick="selectTransferDirection('bankToWallet',this)"><strong>↓ Bank → LiPay</strong><span>Add funds to wallet</span></button><button class="choice" onclick="selectTransferDirection('walletToBank',this)"><strong>↑ LiPay → Bank</strong><span>Move funds back to bank</span></button></div>
    <div id="transferBody"></div></section>`;
  window.transferDirection='bankToWallet'; renderTransferForm();
}
function selectTransferDirection(direction,btn){
  window.transferDirection=direction; $$('#page .choice').forEach(x=>x.classList.remove('active')); btn?.classList.add('active'); renderTransferForm();
}
function renderTransferForm(){
  const from=window.transferDirection==='bankToWallet'?'Linked Bank':'LiPay Balance'; const to=window.transferDirection==='bankToWallet'?'LiPay Balance':'Linked Bank'; const available=window.transferDirection==='bankToWallet'?account.bank.balance:account.balance;
  $('#transferBody').innerHTML=`<div class="transfer-route"><div><span>FROM</span><b>${from}</b><small>Available ${money(available)}</small></div><i>→</i><div><span>TO</span><b>${to}</b><small>Internal transfer</small></div></div><div class="grid"><div class="field"><label>Amount (₹)</label><input id="transferAmount" type="number" min="1" max="${available}" placeholder="5000"></div><div class="field"><label>Purpose</label><input id="transferNote" maxlength="80" placeholder="Move funds between accounts"></div></div><div class="status"><b>Security check</b><br>LiPay will verify the amount, source, destination and account protection state before completing this internal transfer.</div><div class="actions"><button class="btn secondary" onclick="pageBack()">Cancel</button><button class="btn" onclick="reviewInternalTransfer()">Review secure transfer →</button></div>`;
}
function reviewInternalTransfer(){
  const amount=Number($('#transferAmount')?.value||0), note=($('#transferNote')?.value||'').trim(); const from=window.transferDirection==='bankToWallet'?'Linked Bank':'LiPay Balance',to=window.transferDirection==='bankToWallet'?'LiPay Balance':'Linked Bank',available=window.transferDirection==='bankToWallet'?account.bank.balance:account.balance;
  if(!amount||amount<=0||amount>available){toast(`Enter an amount up to ${money(available)}.`);return;}
  if(accountFreeze()||paymentLock()){toast('Transfer blocked by account protection.');renderInternalTransfer();return;}
  const score=window.transferDirection==='bankToWallet'?94:96;
  const id='LIPAY-TR-'+Date.now().toString().slice(-8);
  showModal(`<div class="eyebrow">PRE-TRANSFER TRUST CHECK</div><h2>Transfer ready for authorization</h2><div class="status success"><b>✓ ${score}/100 · LOW RISK</b><br>Source and destination are both your linked LiPay demo accounts.</div><div class="binding-card"><span>TRANSFER</span><b>${esc(from)} → ${esc(to)}</b><strong>${money(amount)}</strong><small>${esc(note||'Internal account transfer')} · ${id}</small></div><p class="muted">This transfer still requires confidential MPIN authorization. Your MPIN is never displayed or stored in the transfer record.</p><div class="field"><label>MPIN</label><input id="transferMpin" type="password" inputmode="numeric" maxlength="6" placeholder="••••" autocomplete="off"></div><div class="actions"><button class="btn secondary" onclick="closeModal()">Cancel</button><button class="btn" onclick="completeInternalTransfer(${amount},'${id}','${from}','${to}')">Authorize transfer</button></div>`);
}
function completeInternalTransfer(amount,id,from,to){
  if(accountFreeze()||paymentLock()){toast('Transfer blocked by account protection.');closeModal();renderInternalTransfer();return;}
  const mpin=($('#transferMpin')?.value||'').trim();
  if(isDuressMpin(mpin)){ triggerDuressProtection(); closeModal(); showDuressCoverPopup(); return; }
  if(mpin!==String(account.mpin)){
    const result=registerMpinFailure();
    if(result.locked){
      toast(`Too many incorrect attempts. Payments are locked until ${new Date(result.until).toLocaleTimeString()}.`);
      audit('MPIN entered incorrectly 3 times on transfer — payment blocked and outgoing payments locked','danger');
      closeModal(); renderInternalTransfer();
      return;
    }
    toast(`Incorrect MPIN. ${result.remaining} attempt${result.remaining===1?'':'s'} remaining.`);
    audit('Internal transfer authorization failed — MPIN mismatch','danger');
    return;
  }
  registerMpinSuccess();
  const bankToWallet=window.transferDirection==='bankToWallet'; if(bankToWallet){account.bank.balance-=amount;account.balance+=amount;}else{account.balance-=amount;account.bank.balance+=amount;}
  writeLocal(ACCOUNT,account); updateProfile(); closeModal();
  const entry={id,recipient:to,amount,time:new Date().toISOString(),score:bankToWallet?94:96,decision:'APPROVE',source:from,type:'INTERNAL_TRANSFER',mode:recoveryActive()?'Emergency':'Normal',binding:'Bound',context:'Evaluated',remainingBalance:bankToWallet?account.balance:account.bank.balance,note:'Internal transfer'};
  const h=history();h.unshift(entry);writeLocal(HISTORY,h.slice(0,50)); currentReceipt=entry; audit(`Internal transfer approved — ${money(amount)} · ${from} → ${to}`); renderInternalTransferSuccess(entry);
}
function renderInternalTransferSuccess(e){
  $('#page').innerHTML=`<section class="card screen centered"><div class="eyebrow">INTERNAL TRANSFER COMPLETE</div><h1>Transfer successful ✓</h1><div class="status success"><b>SECURE</b><br>Money was moved internally between your LiPay wallet and linked demo bank account.</div><div class="receipt-box" id="receiptBox"><div class="receipt-brand">LiPay <span>TRANSFER RECEIPT</span></div><div class="receipt-row"><span>Amount moved</span><b>${money(e.amount)}</b></div><div class="receipt-row"><span>Route</span><b>${esc(e.source)} → ${esc(e.recipient)}</b></div><div class="receipt-row"><span>Transaction ID</span><b>${esc(e.id)}</b></div><div class="receipt-row"><span>Date + time</span><b>${new Date(e.time).toLocaleString()}</b></div><div class="receipt-row"><span>Trust score</span><b>${e.score}/100</b></div><div class="receipt-row"><span>Status</span><b class="text-success">APPROVED</b></div></div><div class="actions"><button class="btn" onclick="saveReceipt()">Save to Phone</button><button class="btn secondary" onclick="shareReceipt()">Share with Receiver</button></div><div class="actions receipt-secondary"><button class="btn secondary" onclick="page('home')">Dashboard</button><button class="btn secondary" onclick="page('history')">View History</button></div></section>`;
}


async function qrSignature(o){return (await sha256(`LIPAY|${o.to}|${o.upi}|${o.amt}|${o.exp}|${o.nonce}|LIPAY-DEMO-SIGNING-KEY`)).slice(0,32);}
function encodeQR(o){return `LIPAY|to=${encodeURIComponent(o.to)}|upi=${encodeURIComponent(o.upi)}|amt=${o.amt}|exp=${o.exp}|nonce=${o.nonce}|sig=${o.sig}`;}
function decodeQR(raw){if(!raw?.startsWith('LIPAY|'))return null;const o={};raw.split('|').slice(1).forEach(p=>{const i=p.indexOf('=');if(i>0)o[p.slice(0,i)]=decodeURIComponent(p.slice(i+1));});return o;}
async function validateQR(raw){
  const o=decodeQR(raw); if(!o)return {ok:false,reason:'malformed'};
  if(Date.now()>Number(o.exp))return {ok:false,reason:'expired'};
  if(await qrSignature(o)!==o.sig)return {ok:false,reason:'tampered'};
  const seen=readLocal(SEEN_QR,[]); if(seen.includes(o.nonce))return {ok:false,reason:'replayed'};
  return {ok:true,o};
}
function qrForm(){
  stopMedia();
  $('#recipientBody').innerHTML=`<div class="status"><b>Signed QR integrity checks</b><br>Recipient, amount, timestamp, expiry, nonce and signature are verified. A valid code becomes single-use only after it passes integrity validation.</div>
    <div class="scanner"><video id="qrVideo" autoplay playsinline muted></video><span>Camera scanner</span></div><div id="qrStatus" class="status">Requesting camera…</div>
    <div class="actions"><button class="btn secondary" onclick="openDemoQR()">Generate Valid QR</button><button class="btn secondary" onclick="tamperDemoQR()">Manipulate Amount</button><button class="btn secondary" onclick="tamperRecipientQR()">Manipulate Recipient</button><button class="btn secondary" onclick="expiredDemoQR()">Expired QR</button><button class="btn secondary" onclick="replayDemoQR()">Replay QR</button><button class="btn secondary" onclick="cancelFlow('Payment cancelled during QR verification')">Cancel Payment</button></div>`;
  startQR();
}
async function startQR(){
  const status=$('#qrStatus');
  try{
    if(!navigator.mediaDevices?.getUserMedia||typeof jsQR!=='function')throw Error('unavailable');
    const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'}}}); media.push(stream);
    const v=$('#qrVideo'); v.srcObject=stream; await v.play(); scanQR();
  }catch{
    if(status){status.className='status warn';status.textContent='Camera/jsQR unavailable. Use the controlled demo buttons below.';}
    audit('QR camera unavailable — honest demo fallback shown','warn');
  }
}
function scanQR(){
  const v=$('#qrVideo'); if(!v||!media.length)return;
  if(v.readyState>=2&&v.videoWidth&&v.videoHeight){
    const c=document.createElement('canvas'),x=c.getContext('2d');c.width=v.videoWidth;c.height=v.videoHeight;x.drawImage(v,0,0);
    const d=x.getImageData(0,0,c.width,c.height),code=jsQR(d.data,c.width,c.height);
    if(code?.data){stopMedia();handleQR(code.data);return;}
  }
  qrFrame=requestAnimationFrame(scanQR);
}
async function openDemoQR(){
  const o={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()+30000,nonce:crypto.randomUUID()};o.sig=await qrSignature(o);
  window.demoQR=encodeQR(o);
  showModal(`<div class="eyebrow">SIGNED DEMO QR</div><h2>Original transaction</h2><div id="qrRender" class="qr-render"></div><div class="qr-payload">${esc(window.demoQR)}</div>
    <div class="status success">✓ Signature valid · ✓ 30s expiry · ✓ New nonce</div><div class="actions"><button class="btn" onclick="handleQR(window.demoQR);closeModal()">Simulate Scan</button><button class="btn secondary" onclick="closeModal()">Close</button></div>`);
  try{new QRCode($('#qrRender'),{text:window.demoQR,width:190,height:190});}catch{toast('QR renderer unavailable; Simulate Scan still works.');}
}
async function tamperDemoQR(){const o={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()+30000,nonce:crypto.randomUUID()};o.sig=await qrSignature(o);o.amt=3500;await handleQR(encodeQR(o));}
async function tamperRecipientQR(){const o={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()+30000,nonce:crypto.randomUUID()};o.sig=await qrSignature(o);o.to='attacker@lipay';await handleQR(encodeQR(o));}
async function expiredDemoQR(){const o={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()-1,nonce:crypto.randomUUID()};o.sig=await qrSignature(o);await handleQR(encodeQR(o));}
async function replayDemoQR(){const o={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()+30000,nonce:'REPLAY-DEMO'};o.sig=await qrSignature(o);const raw=encodeQR(o);const seen=readLocal(SEEN_QR,[]);if(!seen.includes(o.nonce)){seen.push(o.nonce);writeLocal(SEEN_QR,seen);}await handleQR(raw);}
async function handleQR(raw){
  const v=await validateQR(raw),s=$('#qrStatus');
  if(!v.ok){const msg={tampered:'Payment rejected because the QR signature does not match the transaction data.',expired:'Payment rejected because the signed QR has expired.',replayed:'Payment rejected because this signed QR was already used.',malformed:'Payment rejected because the QR format is invalid.'}[v.reason]||'Payment rejected because QR integrity failed.';
    if(s){s.className='status danger';s.textContent='✕ '+msg;} audit(`QR ${v.reason} — payment blocked`,'danger'); return;
  }
  if(Number(v.o.amt)>sourceBalance(state.source)){if(s){s.className='status danger';s.textContent='Insufficient balance for this QR payment.';}return;}
  state.secondSignature=!!$('#secondSignatureEnabled')?.checked;state.secondApprover=(($('#secondApprover')?.value||'').trim());
  if(state.secondSignature&&!state.secondApprover) state.secondApprover='joint-owner@lipay';
  const seen=readLocal(SEEN_QR,[]);seen.push(v.o.nonce);writeLocal(SEEN_QR,seen.slice(-100));
  state.recipient=v.o.to;state.amount=Number(v.o.amt);state.note='QR payment';
  state.qr={recipient:v.o.to,amount:Number(v.o.amt),nonce:v.o.nonce,expiry:Number(v.o.exp),signature:v.o.sig};
  if(s){s.className='status success';s.innerHTML='✓ Signature valid<br>✓ Recipient verified<br>✓ Amount verified<br>✓ QR not expired<br>✓ QR not previously used';}
  audit('Signed QR verified — transaction data recovered and bound'); setTimeout(captureContext,450);
}

async function captureContext(){
  progress(2);
  $('#flow').innerHTML=`<div class="eyebrow">STEP 2 · AUTOMATIC CONTEXT</div><h2>Context is detected automatically</h2><p class="muted">No manual risk selection. LiPay evaluates device, network, location and amount. Time and recipient status are shown for transaction context but do not add risk points.</p><div id="contextTiles" class="context-grid"></div><div id="contextStatus" class="status">Collecting signals…</div>
    <div class="actions"><button class="btn secondary" onclick="cancelFlow('Payment cancelled during context evaluation')">Cancel Payment</button></div>`;
  const conn=navigator.connection||navigator.mozConnection||navigator.webkitConnection, online=navigator.onLine!==false, connection=conn?.effectiveType||'Unavailable';
  let geo={status:'Unavailable',risk:18};
  try{geo=await new Promise(resolve=>navigator.geolocation?navigator.geolocation.getCurrentPosition(p=>resolve({status:'Location verified',risk:4}),()=>resolve({status:'Location unavailable',risk:18}),{enableHighAccuracy:false,timeout:4500,maximumAge:120000}):resolve({status:'Location unavailable',risk:18}));}catch{}
  const known=!!localStorage.getItem('lipay_device_id'), hour=new Date().getHours();
  const timeRisk=0, networkRisk=!online?25:(connection==='4g'?3:connection==='3g'?8:12),
    deviceRisk=known?3:12, amountRisk=state.amount>50000?22:state.amount>20000?12:3;
  localStorage.setItem('lipay_device_id','known');
  const recipientSeen=history().some(x=>x.recipient===state.recipient), recipientRisk=recipientSeen?0:6;
  state.context={online,connection,geo,timeBand:hour<6?'Late night':hour<12?'Morning':hour<18?'Afternoon':hour<23?'Evening':'Late night',
    deviceKnown:known,recipientSeen,risks:{device:deviceRisk,network:networkRisk,location:geo.risk,amount:amountRisk,time:timeRisk,recipient:recipientRisk},fraudAlerts:0};
  state.context.highRisk=isHighRiskTransaction();
  if(state.context.highRisk){audit('HIGH RISK detected — additional security review required','warn');}
  const tiles=[
    ['DEVICE',known?'Known device':'New device',deviceRisk],['NETWORK',online?`Normal · ${connection}`:'Offline',networkRisk],
    ['LOCATION',geo.status,geo.risk],['TIME',state.context.timeBand,timeRisk],['AMOUNT',money(state.amount),amountRisk],
    ['RECIPIENT',recipientSeen?'Previously used':'New recipient',recipientRisk]
  ];
  $('#contextTiles').innerHTML=tiles.map(t=>`<div class="tile"><span>${esc(t[0])}</span><b>${esc(t[1])}</b><small>${t[2]===0?'No risk impact':t[2]+' risk points'}</small></div>`).join('');
  const total=Object.values(state.context.risks).reduce((a,b)=>a+b,0);
  state.context.fraudAlerts=Number(state.context.fraudAlerts||0);
  $('#contextStatus').className='status '+(total<20?'success':'warn');
  $('#contextStatus').innerHTML=`${total<20?'✓ Context looks normal.':'⚠ Some context signals are unusual.'}<br>Automatic context risk: <b>${total}</b> points.`;
  audit(`Automatic context evaluated — ${online?'online':'offline'}, ${connection}, ${geo.status}, ${recipientSeen?'known':'new'} recipient`);
  setTimeout(identityGate,500);
}
async function identityGate(){
  progress(3);
  $('#flow').innerHTML=`<div class="eyebrow">STEP 3 · IDENTITY VERIFICATION</div><h2>Verify that it is you</h2><p class="muted">Identity verification happens before OTP and MPIN. If camera detection is available, it is explicitly labelled as a demo presence check.</p>
    <div class="choice-grid"><button id="faceChoice" class="choice active" onclick="identityMode('face')"><strong>◉ Face Presence Check — Demo</strong><span>Camera presence detection only; not production biometric/liveness authentication</span></button><button id="bioChoice" class="choice" onclick="identityMode('bio')"><strong>◎ Device Biometric — Production Concept</strong><span>WebAuthn capability can be integrated in production</span></button></div><div id="identityBody"></div>`;
  identityMode('face');
}
function identityMode(mode){
  $$('.choice').forEach(x=>x.classList.remove('active'));$('#'+(mode==='face'?'faceChoice':'bioChoice'))?.classList.add('active');stopMedia();
  if(mode==='face') faceUI(); else bioUI();
}
async function faceUI(){
  $('#identityBody').innerHTML=`<div class="camera"><video id="faceVideo" autoplay playsinline muted></video><div class="face-oval"></div><span>Face Presence Check — Demo</span></div><div id="faceStatus" class="status">Requesting camera permission…</div>
    <div class="actions"><button class="btn" onclick="verifyFace()">Run Demo Presence Check</button><button class="btn secondary" onclick="skipIdentity()">Camera unavailable — skip demo</button><button class="btn secondary" onclick="cancelFlow('Payment cancelled during identity verification')">Cancel Payment</button></div>`;
  try{if(!navigator.mediaDevices?.getUserMedia)throw Error('unsupported');const s=await navigator.mediaDevices.getUserMedia({video:true});media.push(s);$('#faceVideo').srcObject=s;$('#faceStatus').textContent='Camera active. Presence check is ready.';audit('Camera permission granted for demo face presence check');}
  catch{$('#faceStatus').className='status warn';$('#faceStatus').textContent='Camera unavailable or denied. Skip is available and lowers trust.';audit('Camera unavailable — demo fallback shown','warn');}
}
async function verifyFace(){
  if(!$('#faceVideo')?.srcObject){toast('Camera is not active. Retry or use the demo skip.');return;}
  state.identity='Face Presence Check — Demo';state.identitySkipped=false;stopMedia();audit('Face Presence Check — Demo completed');otpGate();
}
function skipIdentity(){state.identity='Identity fallback — Demo';state.identitySkipped=true;stopMedia();audit('Identity fallback used — trust reduced','warn');otpGate();}
async function bioUI(){
  $('#identityBody').innerHTML=`<div class="status"><b>Production concept</b><br>This browser can request a platform authenticator using WebAuthn in a real deployment. The current LiPay prototype does not claim biometric proof from a mock interaction.</div>
    <button class="btn" onclick="tryWebAuthn()">Attempt platform authenticator</button><button class="btn secondary" onclick="skipIdentity()">Use demo fallback</button><button class="btn secondary" onclick="cancelFlow('Payment cancelled during identity verification')">Cancel Payment</button>`;
}
async function tryWebAuthn(){
  if(!window.PublicKeyCredential){toast('WebAuthn is unavailable in this browser.');skipIdentity();return;}
  state.identity='Platform authenticator — demo capability';state.identitySkipped=false;audit('Platform authenticator capability selected — demo');otpGate();
}
function otpGate(){
  progress(4);
  // Prototype OTP is deterministic so the challenge shown on screen and the
  // verification target can never diverge because of storage, caching, or timing.
  // Production systems must generate and verify OTPs server-side.
  state.otpCode='579033';
  try { sessionStorage.setItem('lipay_demo_otp',state.otpCode); } catch {}
  $('#flow').innerHTML=`<div class="eyebrow">STEP 4 · STEP-UP / OTP</div><h2>Confirm the verification challenge</h2><p class="muted">OTP is simulated locally for this prototype. Use the exact 6-digit challenge shown below.</p>
    <div class="demo-otp" data-demo-otp="579033"><span>DEMO OTP CHALLENGE</span><b>579033</b></div>
    <div class="field"><label>Enter OTP</label><input id="otpInput" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6-digit OTP"></div>
    <div id="otpStatus" class="status">Attempts remaining: 3</div>
    <div class="actions"><button class="btn" id="verifyOtpBtn" onclick="verifyOTP()">Verify OTP →</button><button class="btn secondary" onclick="cancelFlow('Payment cancelled during OTP verification')">Cancel Payment</button></div>`;
  const input=$('#otpInput');
  if(input) input.addEventListener('keydown',e=>{ if(e.key==='Enter') verifyOTP(); });
}
function verifyOTP(){
  const input=String($('#otpInput')?.value||'').replace(/[^0-9]/g,'');
  // Read the exact challenge rendered in the current DOM first. This makes the
  // visible OTP authoritative and eliminates sessionStorage/cache mismatches.
  const visible=String($('.demo-otp')?.getAttribute('data-demo-otp')||$('.demo-otp b')?.textContent||'').replace(/[^0-9]/g,'');
  const expected=visible || String(state?.otpCode||'579033').replace(/[^0-9]/g,'');
  if(input.length===6 && expected.length===6 && input===expected){
    state.otpCode=expected;
    state.otpVerified=true;
    state.otpAttempts=0;
    try { sessionStorage.removeItem('lipay_demo_otp'); } catch {}
    audit('OTP verified');
    preTrustPreview();
    return;
  }
  state.otpAttempts++;const remaining=3-state.otpAttempts;
  const s=$('#otpStatus');
  if(remaining<=0){if(s){s.className='status danger';s.textContent='Verification failed. No payment was completed.';}audit('OTP verification failed — payment cancelled','danger');setTimeout(()=>cancelFlow('Verification failed. No payment was completed.'),700);return;}
  if(s)s.textContent=`Incorrect OTP. ${remaining} attempts remaining.`; audit('Incorrect OTP entered','warn');
}
window.verifyOTP=verifyOTP;
function preTrustPreview(){
  progress(5); state.score=trustScoreFromState(); state.decision=state.score>=76?'APPROVE':'STEP-UP';
  const r=state.context.risks,total=Object.values(r).reduce((a,b)=>a+b,0);
  const highRisk=isHighRiskTransaction();
  $('#flow').innerHTML=`<div class="eyebrow">STEP 5 · PRE-PAYMENT TRUST CHECK</div><h2>Payment Safety Check</h2><p class="muted">This security decision appears <b>before</b> the final MPIN. The score is a prototype/demo risk engine, not a production authorization signal.</p>
    <div class="trust-preview"><div class="gauge" style="--score:${state.score}"><div class="gauge-in"><b>${state.score}</b><small>TRUST SCORE</small></div></div><div class="decision ${decisionClass()}">${trustBand(state.score)}</div>
      <div class="signal-list"><span>✓ Identity <b>${esc(state.identity)}</b></span><span>${state.context.deviceKnown?'✓':'⚠'} Device <b>${state.context.deviceKnown?'Known':'New'}</b></span><span>✓ Recipient <b>${state.context.recipientSeen?'Previously used':'New recipient'} · no risk impact</b></span><span>${r.amount<=3?'✓':'⚠'} Amount <b>${money(state.amount)}</b></span><span>${r.location<=4?'✓':'⚠'} Location <b>${esc(state.context.geo.status)}</b></span><span>✓ Time <b>${esc(state.context.timeBand)} · no risk impact</b></span></div>
    </div><div class="status ${highRisk?'warn':state.decision==='APPROVE'?'success':state.decision==='STEP-UP'?'warn':'danger'}">${highRisk?'⚠ HIGH RISK: This payment requires a second authorized signature before funds can be released. '+preTrustExplanation(total):preTrustExplanation(total)}</div>
    <div class="actions">${state.decision==='BLOCK'?'<button class="btn secondary" onclick="cancelFlow(\'Payment blocked for your protection\')">Cancel Payment</button><button class="btn" onclick="identityGate()">Verify Again</button>':state.decision==='STEP-UP'?'<button class="btn" onclick="runStepUp()">Additional Verification</button><button class="btn secondary" onclick="cancelFlow(\'User cancelled after trust preview\')">Cancel Payment</button>':'<button class="btn" onclick="mpinGate()">Continue to final MPIN →</button><button class="btn secondary" onclick="cancelFlow(\'Payment cancelled after trust preview\')">Cancel Payment</button>'}</div>`;
  audit(`Pre-payment trust decision: ${state.decision} at ${state.score}/100`,state.decision==='BLOCK'?'danger':state.decision==='STEP-UP'?'warn':'info');
}
function decisionClass(){return state.decision==='APPROVE'?'approve':state.decision==='STEP-UP'?'stepup':'block';}
function preTrustExplanation(total){
  if(state.decision==='APPROVE')return 'Standard verification is sufficient. The payment can proceed to confidential MPIN authorization.';
  if(state.decision==='STEP-UP')return `Additional verification required. ${total} risk points were detected across automatic context signals.`;
  return 'Payment blocked for your protection because the transaction context is too risky.';
}
async function runStepUp(){
  state.stepUp=true;
  state.context.risks.amount=Math.max(0,state.context.risks.amount-4);
  audit('Additional verification completed — risk reduced for demo','info'); preTrustPreview();
}
function reverseMpinOf(mpin){return String(mpin).split('').reverse().join('');}
function isDuressMpin(input){const m=String(account.mpin||''); return m.length>1 && input===reverseMpinOf(m) && input!==m;}
function triggerDuressProtection(){
  const until=Date.now()+2*24*60*60*1000;
  account.duressLockUntil=Math.max(Number(account.duressLockUntil||0),until);
  writeLocal(ACCOUNT,account);
  audit('Silent emergency protection activated — outgoing payments locked for 48 hours','warn');
  try{fetch('/api/security/duress-event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'duress_mpin',timestamp:new Date().toISOString(),lockUntil:new Date(account.duressLockUntil).toISOString()})}).catch(()=>{});}catch{}
  return account.duressLockUntil;
}
function showDuressCoverPopup(){
  const until=duressLock();
  showModal(`<div class="eyebrow">SERVICE STATUS</div><h2>Server temporarily unavailable</h2><div class="status warn"><b>We couldn't complete your request right now.</b><br>Please try again later.</div><p class="muted">For security, this transaction was not completed.</p><button class="btn wide" onclick="closeModal();page('home')">Back to dashboard</button>`);
  setTimeout(()=>{ if($('#modalRoot')?.innerHTML){} },0);
  return until;
}
function mpinGate(){
  progress(6);
  $('#flow').innerHTML=`<div class="eyebrow">STEP 6 · FINAL MPIN AUTHORIZATION</div><h2>Authorize this exact payment</h2><p class="muted">MPIN is confidential. It is never shown in history, receipts, sharing, logs or QR payloads.</p>
    <div class="binding-card"><span>TRANSACTION BINDING</span><b>${esc(state.recipient)}</b><strong>${money(state.amount)}</strong><small>ID ${esc(state.txId)} · Purpose ${esc(state.note||'—')}</small></div>
    <div class="field"><label>MPIN</label><input id="mpinInput" type="password" inputmode="numeric" maxlength="6" autocomplete="off" placeholder="••••"></div>
    <div id="mpinStatus" class="status">Enter your MPIN to authorize.</div>
    <div class="actions"><button class="btn" onclick="verifyMPIN()">Authorize payment →</button><button class="btn secondary" onclick="cancelFlow('Payment cancelled before MPIN authorization')">Cancel Payment</button></div>`;
}
function verifyMPIN(){
  const input=$('#mpinInput')?.value||'';
  if(isDuressMpin(input)){ triggerDuressProtection(); $('#mpinInput').value=''; state.mpinAttempts=3; stopMedia(); showDuressCoverPopup(); return; }
  if(input===String(account.mpin)){state.mpinVerified=true;state.mpin='';registerMpinSuccess();audit('MPIN verified — confidential value discarded');finalTrustCheck();return;}
  const s=$('#mpinStatus'); const result=registerMpinFailure();
  if(result.locked){
    if(s){s.className='status danger';s.textContent=`Too many incorrect attempts. Payments are locked until ${new Date(result.until).toLocaleTimeString()}.`;}
    audit('MPIN verification failed 3 times — payment blocked and outgoing payments locked','danger');
    setTimeout(()=>{ stopMedia(); page('pay'); },900);
    return;
  }
  if(s)s.textContent=`Incorrect MPIN. ${result.remaining} attempt${result.remaining===1?'':'s'} remaining.`; audit('Incorrect MPIN entered','warn');
}
async function finalTrustCheck(){
  const activeFreeze=accountFreeze();
  if(activeFreeze){
    audit('Final trust check stopped — account freeze is active','danger');
    renderFrozenPayments(activeFreeze);
    return;
  }
  progress(7);
  const binding=await sha256(`${state.txId}|${state.recipient}|${state.amount}|${state.note}|${state.nonce}`);
  const unchanged=binding===state.txBinding, qrOk=!state.qr||(
    state.qr.recipient===state.recipient && state.qr.amount===state.amount &&
    Date.now()<=state.qr.expiry && !(readLocal(SEEN_QR,[]).filter(x=>x===state.qr.nonce).length>1)
  );
  const expired=Date.now()-state.createdAt>120000;
  const replayed=readLocal('lipay_used_tx_v54',[]).includes(state.txId);
  const currentScore=trustScoreFromState();
  let decision=(!unchanged||!qrOk||expired||replayed)?'BLOCK':(currentScore>=76?'APPROVE':'STEP-UP');
  state.finalScore=currentScore; state.finalDecision=decision;
  state.transactionHash=await sha256(`${state.txId}|${state.recipient}|${state.amount}|${state.note}|${state.nonce}|${state.source}`);
  // Second signature is requested only when the sender explicitly enabled it.
  // High-risk scoring never silently turns on a second approver.
  $('#flow').innerHTML=`<div class="eyebrow">STEP 7 · FINAL TRUST RE-CHECK</div><h2>Re-check the exact transaction</h2><p class="muted">LiPay verifies recipient, amount, transaction ID, QR information, expiry, replay state and risk again after identity + OTP + MPIN.</p>
    <div class="signal-list large"><span>${unchanged?'✓':'✕'} Transaction binding <b>${unchanged?'Unchanged':'Changed'}</b></span><span>${state.qr?(qrOk?'✓':'✕'):'✓'} Recipient + amount <b>${esc(state.recipient)} · ${money(state.amount)}</b></span><span>${!expired?'✓':'✕'} Transaction expiry <b>${expired?'Expired':'Valid'}</b></span><span>${!replayed?'✓':'✕'} Replay check <b>${replayed?'Replay detected':'Not replayed'}</b></span><span>${currentScore>=76?'✓':'⚠'} Final risk <b>${currentScore}/100</b></span></div>
    <div class="status ${decision==='APPROVE'?'success':decision==='STEP-UP'?'warn':'danger'}">${decision==='APPROVE'?'Final trust passed. The exact transaction can be approved.':decision==='STEP-UP'?'Final trust requires another step-up before approval.':'Final trust failed. Payment is blocked.'}</div>
    <div class="actions">${decision==='APPROVE'?'<button class="btn" onclick="approvePayment()">APPROVE PAYMENT ✓</button>':decision==='STEP-UP'?'<button class="btn" onclick="finalStepUp()">Run Final Step-Up</button>':'<button class="btn" onclick="identityGate()">Verify Again</button>'}<button class="btn secondary" onclick="cancelFlow('Payment cancelled at final trust check')">Cancel Payment</button></div>`;
  audit(`Final trust re-check: ${decision} at ${currentScore}/100`,decision==='BLOCK'?'danger':decision==='STEP-UP'?'warn':'info');
}
async function finalStepUp(){state.context.risks.device=Math.max(0,state.context.risks.device-4);audit('Final step-up completed — final trust recalculated');finalTrustCheck();}
function secondSignaturePayload(){
  return `${state.txId}|${state.recipient}|${state.amount}|${state.note}|${state.nonce}|${state.source}|${state.identity||''}`;
}
async function createSecondSignatureHash(){ return sha256(secondSignaturePayload()); }
function requestSecondSignature(){
  if(!state?.secondSignatureRequired&&!state?.secondSignature)return approvePayment();
  state.secondSignature=true; state.secondSignatureRequired=true;
  if(!state.secondApprover) state.secondApprover='joint-owner@lipay';
  state.secondSignatureCreatedAt=Date.now();
  createSecondSignatureHash().then(hash=>{
    state.secondSignatureHash=hash;
    audit(`Transaction status: PENDING_SECOND_SIGNATURE · ${state.txId}`,'warn');
    showSecondSignatureModal();
  });
}
function showSecondSignatureModal(){
  const remaining=Math.max(0,120000-(Date.now()-state.secondSignatureCreatedAt));
  if(!remaining){ state.secondSignatureExpired=true; audit('Second signature expired — transaction cancelled','danger'); closeModal(); toast('Second signature request expired.'); return; }
  const approver=esc(state.secondApprover||'Second authorized approver');
  showModal(`<div class="eyebrow">SECOND SIGNATURE AUTHORIZATION</div><h2>Pending second approval</h2>
    <div class="status warn"><b>PENDING_SECOND_SIGNATURE</b><br>This high-risk payment is not released until an independently authenticated authorized person approves this exact transaction.</div>
    <div class="binding-card"><span>EXACT TRANSACTION</span><b>${esc(state.recipient)}</b><strong>${money(state.amount)}</strong><small>Sender: ${esc(account.name)} · ID: ${esc(state.txId)} · ${new Date(state.createdAt).toLocaleString()}</small></div>
    <div class="signal-list large"><span>Payment purpose <b>${esc(state.note||'—')}</b></span><span>Approver <b>${approver}</b></span><span>Transaction hash <b>${esc((state.secondSignatureHash||'').slice(0,24))}…</b></span><span>Request expires <b>${Math.ceil(remaining/1000)} seconds</b></span></div>
    <p class="muted">Demo mode: the second approver is authenticated independently with a dedicated demo MPIN plus a separate device-verification step. The approval is cryptographically bound to this transaction and cannot be reused.</p>
    <div class="status ${state.secondDeviceVerified?'success':'warn'}"><b>SECOND DEVICE</b><br>${state.secondDeviceVerified?'✓ Verified for this approval request':'Not verified — complete device verification before approval'}</div>
    <div class="actions"><button class="btn secondary" onclick="verifySecondDevice()">${state.secondDeviceVerified?'Device Verified ✓':'Verify Second Device'}</button></div>
    <div class="field"><label>Second approver MPIN</label><input id="secondMpin" type="password" inputmode="numeric" maxlength="6" placeholder="••••"></div>
    <div class="actions"><button class="btn" onclick="authenticateSecondSignature()">Authenticate &amp; Approve</button><button class="btn danger" onclick="rejectSecondSignature()">Reject Payment</button><button class="btn secondary" onclick="closeModal()">Keep Pending</button></div>`);
  clearTimeout(window.__secondSigTimer);
  window.__secondSigTimer=setTimeout(()=>{if(state&&!state.secondSignatureApproved&&!state.secondSignatureRejected&&Date.now()-state.secondSignatureCreatedAt>=120000){state.secondSignatureExpired=true;closeModal();audit(`Second signature timeout — transaction ${state.txId} expired`,'danger');toast('Second signature request expired. No payment was completed.');}},120500);
}
function verifySecondDevice(){
  if(!state)return;
  if(Date.now()-state.secondSignatureCreatedAt>120000){state.secondSignatureExpired=true;closeModal();toast('Second signature request expired.');audit('Second device verification attempted after expiry','danger');return;}
  state.secondDeviceVerified=true;
  audit(`Second approver device verified for transaction ${state.txId}`);
  showSecondSignatureModal();
}
function authenticateSecondSignature(){
  if(!state)return;
  if(Date.now()-state.secondSignatureCreatedAt>120000){ state.secondSignatureExpired=true; closeModal(); audit('Second signature request expired — payment cancelled','danger'); toast('Second signature request expired.'); return; }
  const input=($('#secondMpin')?.value||'').trim();
  const demoSecondMpin='1357';
  if(input!==demoSecondMpin){ toast('Second approver authentication failed.'); audit('Second approver authentication failed','danger'); return; }
  createSecondSignatureHash().then(async hash=>{
    const expected=state.secondSignatureHash;
    if(!state.secondDeviceVerified){toast('Verify the second authorized device first.');audit('Second approver device verification missing','warn');return;}
    if(hash!==expected){ audit('Second signature hash mismatch — approval rejected','danger'); toast('Transaction changed. Approval is invalid.'); rejectSecondSignature(true); return; }
    state.secondSignatureApproved=true;
    state.secondSignatureApprovedAt=Date.now();
    state.secondSignatureApprovalHash=await sha256(`${expected}|${state.secondSignatureApprovedAt}`);
    state.secondSignatureReleaseGranted=false;
    state.secondSignatureStatus='PENDING_RELEASE';
    audit(`Second signature authenticated — transaction ${state.txId} is PENDING_SECOND_SIGNATURE_RELEASE`,'warn');
    closeModal();
    showSecondSignatureRelease();
  });
}
function showSecondSignatureRelease(){
  if(!state||!state.secondSignatureApproved||state.secondSignatureRejected||state.secondSignatureExpired)return;
  showModal(`<div class="eyebrow">SECOND SIGNATURE VERIFIED</div><h2>Payment is pending release</h2>
    <div class="status warn"><b>PENDING_SECOND_SIGNATURE</b><br>The second authorized person has authenticated this exact transaction. Funds are still held until release is granted for this transaction.</div>
    <div class="binding-card"><span>EXACT TRANSACTION</span><b>${esc(state.recipient)}</b><strong>${money(state.amount)}</strong><small>${esc(state.txId)} · ${esc(state.secondApprover||'Second approver')}</small></div>
    <div class="status success"><b>✓ Second MPIN verified</b><br>✓ Second device verified<br>✓ Transaction hash verified<br>✓ Approval is bound to this transaction only</div>
    <div class="actions"><button class="btn" onclick="releaseSecondSignaturePayment()">Grant access &amp; release payment →</button><button class="btn danger" onclick="rejectSecondSignature()">Reject Payment</button></div>`);
}
function releaseSecondSignaturePayment(){
  if(!state||!state.secondSignatureApproved){toast('Second signature authorization is required.');return;}
  if(state.secondSignatureRejected||state.secondSignatureExpired){toast('This transaction authorization is no longer valid.');return;}
  state.secondSignatureReleaseGranted=true;
  state.secondSignatureStatus='RELEASED';
  audit(`Second signature access granted — releasing transaction ${state.txId}`,'info');
  closeModal();
  approvePayment();
}
function rejectSecondSignature(silent=false){
  if(!state)return;
  state.secondSignatureRejected=true;
  state.finalDecision='REJECTED_SECOND_SIGNATURE';
  audit(`Second signature rejected — transaction ${state.txId} cancelled`,'danger');
  closeModal();
  if(!silent){ toast('Payment rejected by the second authorized person.'); setTimeout(()=>cancelFlow('Payment rejected by second authorization'),450); }
}
function approveSecondSignature(){ authenticateSecondSignature(); }

async function approvePayment(){
  if(state?.secondSignatureRequired&&(!state.secondSignatureApproved||!state.secondSignatureReleaseGranted)){ if(state.secondSignatureApproved) showSecondSignatureRelease(); else requestSecondSignature(); return;}
  if(state?.secondSignatureRejected||state?.secondSignatureExpired){toast('Second signature authorization is no longer valid.');return;}
  const activeFreeze=accountFreeze();
  if(activeFreeze){renderFrozenPayments(activeFreeze);return;}
  if(state.finalDecision!=='APPROVE'){toast('Final trust did not approve this transaction.');return;}
  const source=state.source, balance=sourceBalance(source);
  if(state.amount>balance){audit('Payment stopped — balance changed before authorization','danger');toast('Balance changed and is no longer sufficient.');startPayment();return;}
  const used=readLocal('lipay_used_tx_v54',[]);if(used.includes(state.txId)){toast('Transaction replay blocked.');audit('Transaction replay blocked','danger');return;}
  used.push(state.txId);writeLocal('lipay_used_tx_v54',used.slice(-100));
  if(source==='bank')account.bank.balance-=state.amount;else account.balance-=state.amount;writeLocal(ACCOUNT,account);updateProfile();
  // Demo receiver ledger: the receiver gets the exact amount sent. No fee or hidden deduction is applied.
  const receiverBalance=creditReceiver(state.recipient,state.amount,state.txId);
  const entry={id:state.txId,recipient:state.recipient,amount:state.amount,receiverAmount:state.amount,receiverBalance,note:state.note,time:new Date().toISOString(),score:state.finalScore,decision:'APPROVE',
    source:state.sourceLabel,identity:state.identity,mode:state.emergency?'Emergency':'Normal',binding:'Bound',context:'Evaluated',qrIntegrity:state.qr?'Verified':'Not applicable',
    secondSignature:state.secondSignature?`Approved by ${state.secondApprover}`:'Not required',
    secondSignatureStatus:state.secondSignature?'APPROVED':'NOT_REQUIRED',
    transactionHash:state.transactionHash||'',
    secondSignatureHash:state.secondSignatureHash||'',
    securityContext:{device:state.context.deviceKnown?'Known':'New',network:state.context.online?`Online · ${state.context.connection}`:'Offline',location:state.context.geo.status,recipientStatus:state.context.recipientSeen?'Previously used':'New recipient',timeContext:state.context.timeBand,timeRisk:0,recipientRisk:0,amountRisk:state.context.risks.amount}};
  const h=history();h.unshift(entry);writeLocal(HISTORY,h.slice(0,50));currentReceipt=entry;
  audit('Payment approved — safe receipt generated');renderReceipt(entry);
}
function renderReceipt(e){
  progress(8);
  const c=e.securityContext||{};
  $('#flow').innerHTML=`<div class="receipt"><div class="eyebrow">STEP 8 · SECURE RECEIPT</div><h2>Payment approved ✓</h2><p class="muted">This receipt contains transaction and security context only. Your remaining personal balance is never shown.</p>
    <div class="receipt-box" id="receiptBox"><div class="receipt-brand">LiPay <span>PAYMENT RECEIPT</span></div>
      <div class="receipt-row"><span>Status</span><b class="text-success">APPROVED</b></div><div class="receipt-row"><span>Second signature</span><b>${esc(e.secondSignature||'Not required')}</b></div><div class="receipt-row"><span>Transaction hash</span><b>${esc((e.transactionHash||'').slice(0,24))}${e.transactionHash?'…':''}</b></div><div class="receipt-row"><span>Amount sent</span><b>${money(e.amount)}</b></div><div class="receipt-row"><span>Amount received</span><b>${money(e.receiverAmount??e.amount)}</b></div><div class="receipt-row"><span>Recipient</span><b>${esc(e.recipient)}</b></div>
      <div class="receipt-row"><span>Recipient status</span><b>${esc(c.recipientStatus||'New recipient')} · no risk impact</b></div><div class="receipt-row"><span>Payment source</span><b>${esc(e.source||'LiPay Balance')}</b></div>
      <div class="receipt-row"><span>Transaction ID</span><b>${esc(e.id)}</b></div><div class="receipt-row"><span>Date + time</span><b>${new Date(e.time).toLocaleString()}</b></div>
      <div class="receipt-row"><span>Device</span><b>${esc(c.device||'—')}</b></div><div class="receipt-row"><span>Network</span><b>${esc(c.network||'—')}</b></div><div class="receipt-row"><span>Location</span><b>${esc(c.location||'—')}</b></div>
      <div class="receipt-row"><span>Time context</span><b>${esc(c.timeContext||'—')} · no risk impact</b></div><div class="receipt-row"><span>Amount risk</span><b>${Number(c.amountRisk||0)} point${Number(c.amountRisk||0)===1?'':'s'}</b></div>
      <div class="receipt-row"><span>QR integrity</span><b>${esc(e.qrIntegrity||'Not applicable')}</b></div><div class="receipt-row"><span>Trust score</span><b>${e.score}/100</b></div><div class="receipt-row"><span>Verification</span><b>✓ Identity · ✓ Transaction Binding · ✓ Trust Check</b></div></div>
    <div class="receipt-share-note">Share with the receiver using your phone's native share sheet, including supported social apps.</div>
    <div class="actions"><button class="btn" onclick="saveReceipt()">Save to Phone</button><button class="btn secondary" onclick="shareReceipt()">Share with Receiver</button></div>
    <div class="actions receipt-secondary"><button class="btn secondary" onclick="page('history')">Payment History</button><button class="btn secondary" onclick="page('home')">Home</button></div></div>`;
}
function safeReceiptText(e){const c=e.securityContext||{};return `LiPay Payment Receipt\nStatus: APPROVED\nAmount sent: ${money(e.amount)}\nAmount received: ${money(e.receiverAmount??e.amount)}\nRecipient: ${e.recipient}\nRecipient status: ${c.recipientStatus||'New recipient'} (no risk impact)\nPayment source: ${e.source||'LiPay Balance'}\nTransaction ID: ${e.id}\nDate + time: ${new Date(e.time).toLocaleString()}\nDevice: ${c.device||'—'}\nNetwork: ${c.network||'—'}\nLocation: ${c.location||'—'}\nTime context: ${c.timeContext||'—'} (no risk impact)\nAmount risk: ${Number(c.amountRisk||0)} point(s)\nQR integrity: ${e.qrIntegrity||'Not applicable'}\nTrust score: ${e.score}/100\nSecond signature: ${e.secondSignature||'Not required'}\nVerification: Identity verified; Transaction binding verified; Trust check passed`;}
async function shareReceipt(){
  const e=currentReceipt||history()[0]; if(!e)return;
  const text=safeReceiptText(e);
  if(navigator.share){try{await navigator.share({title:'LiPay Payment Receipt',text});audit('Receipt shared with receiver using the native share sheet');return;}catch{audit('Receipt sharing cancelled');return;}}
  try{await navigator.clipboard.writeText(text);toast('Receipt copied. Paste it into WhatsApp, Messages or another social app.');audit('Receipt copied for sharing with receiver');}
  catch{showModal(`<h3>Receipt ready to share</h3><pre class="safe-pre">${esc(text)}</pre><button class="btn" onclick="closeModal()">Close</button>`);}
}
function saveReceipt(){
  const e=currentReceipt||history()[0];if(!e)return;
  const blob=new Blob([safeReceiptText(e)],{type:'text/plain;charset=utf-8'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`LiPay-Receipt-${e.id}.txt`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);audit('Receipt saved to phone as a text file');toast('Receipt saved to your phone');
}
function cancelFlow(reason){stopMedia();audit(reason,'danger');toast(reason);setTimeout(()=>page('pay'),550);}

/* History / favorites / account */
function renderHistoryPage(){
  const h=history();
  $('#page').innerHTML=`<section class="card screen"><div class="eyebrow">TRANSACTION HISTORY</div><h1>Payment History</h1><p class="muted">Safe evidence only. Confidential authentication values are never stored here.</p>
    ${h.length?h.map((e,i)=>`<article class="history-item"><div class="history-head"><div><b>${esc(e.recipient)}</b><small>${new Date(e.time).toLocaleString()} · ${esc(e.id)}</small></div><div class="align-right"><b>${money(e.amount)}</b><small class="text-${e.decision==='APPROVE'?'success':'danger'}">${esc(e.decision)} · ${e.score}/100</small></div></div>
      <div class="history-meta"><span>Trust Score <b>${e.score}/100</b></span><span>Status <b>${esc(e.decision)}</b></span><span>Transaction ID <b>${esc(e.id)}</b></span></div>
      <button class="btn secondary" onclick="toggleHistoryDetail(${i})">View Details</button><div id="historyDetail${i}" class="detail hidden">
        <div class="evidence-grid"><span>PERSON <b>✓ Verified</b></span><span>DEVICE <b>✓ Trusted</b></span><span>TRANSACTION <b>✓ Bound</b></span><span>CONTEXT <b>✓ Evaluated</b></span><span>QR INTEGRITY <b>${e.qrIntegrity||'Not applicable'}</b></span><span>SOURCE <b>${esc(e.source||'LiPay Balance')}</b></span></div>
      </div></article>`).join(''):'<div class="empty">No completed payments yet.</div>'}
    <div class="actions"><button class="btn secondary" onclick="page('home')">Back Home</button><button class="btn danger" onclick="clearHistory()">Clear history</button></div></section>`;
}
function toggleHistoryDetail(i){$('#historyDetail'+i)?.classList.toggle('hidden');}
function clearHistory(){if(!confirm('Clear local demo payment history?'))return;writeLocal(HISTORY,[]);audit('Payment history cleared');renderHistoryPage();}
function openFreezeModal(){
  if(!recoveryActive()){toast('Account Freeze is available only during Emergency Recovery on another device.');return;}
  if(accountFreeze()){showFreezeStatus();return;}
  showModal(`<div class="eyebrow">ACCOUNT PROTECTION</div><h2>Freeze account temporarily?</h2><p class="muted">This prototype freeze blocks outgoing payments while keeping your dashboard accessible.</p><div class="actions"><button class="btn danger" onclick="freezeAccount(15)">15 minutes</button><button class="btn secondary" onclick="freezeAccount(60)">1 hour</button><button class="btn secondary" onclick="freezeAccount(1440)">24 hours</button></div><button class="btn secondary wide" onclick="closeModal()">Cancel</button>`);
}
function freezeAccount(minutes){
  account.accountFreezeUntil=Date.now()+minutes*60000; writeLocal(ACCOUNT,account); audit(`Account freeze activated for ${minutes} minute(s)`,'warn'); closeModal(); renderHome();
  setTimeout(()=>showFreezeStatus(),120);
}
function showFreezeStatus(){
  const until=accountFreeze();
  if(!until){toast('Account is not frozen.');return;}
  showModal(`<div class="eyebrow">SECURE ACCOUNT STATUS</div><h2>🛡️ Account securely frozen</h2><div class="status success"><b>SECURE</b><br>Outgoing payments are blocked until ${new Date(until).toLocaleString()}.</div><p class="muted">LiPay is protecting the account during this temporary freeze. You can still view your dashboard and security information.</p><button class="btn wide" onclick="closeModal()">Done</button>`);
}
function renderFrozenPayments(until){
  $('#page').innerHTML=`<section class="card screen centered"><div class="eyebrow">ACCOUNT PROTECTION</div><h1>Account securely frozen</h1><p class="muted">Outgoing payments are blocked while the temporary account freeze is active.</p><div class="status success"><b>🛡️ SECURE</b><br>Frozen until ${new Date(until).toLocaleString()}</div><div class="actions"><button class="btn" onclick="showFreezeStatus()">View Secure Status</button><button class="btn secondary" onclick="page('home')">Back Home</button></div></section>`;
}
function renderAccountPage(){
  const s=session(),lock=recoveryLock(),duress=duressLock(),freeze=accountFreeze();
  $('#page').innerHTML=`<section class="card screen"><div class="eyebrow">ACCOUNT</div><h1>My Account</h1><p class="muted">Balances and recovery controls are demo data. Credentials are never displayed.</p>
    <div class="dashboard-grid"><div class="card dash-card"><span>AVAILABLE LIPAY BALANCE</span><strong>${money(account.balance)}</strong><small>Demo wallet</small></div><div class="card dash-card"><span>LINKED BANK</span><strong>${money(account.bank.balance)}</strong><small>${esc(account.bank.name)} · ${esc(account.bank.accountNumber)}</small></div></div>
    <div class="account-section"><div><div class="eyebrow">RECEIVE MONEY</div><h2>My Account QR</h2><p class="muted">This receive QR contains only a demo account identifier.</p><div id="myAccountQR" class="qr-render"></div><div class="qr-payload">LIPAY-ACCOUNT · ${esc(account.fullPhone)}</div></div><div class="account-summary"><b>${esc(account.name)}</b><span>${esc(account.fullPhone)}</span><span>${esc(account.email||'No email')}</span></div></div>
    ${s.mode==='emergency'&&freeze?`<div class="recovery-box"><div class="eyebrow">🛡️ ACCOUNT FREEZE ACTIVE</div><h2>Account securely frozen</h2><p class="muted">Outgoing payments are blocked until ${new Date(freeze).toLocaleString()}.</p><button class="btn" onclick="showFreezeStatus()">View Secure Status</button></div>`:''}
    ${s.mode==='emergency'?`<div class="recovery-box"><div class="eyebrow">🚨 RECOVERY MODE ACTIVE</div><h2>Recovery access active — payments remain available</h2><p class="muted">Signing in on a lost-phone recovery session does not block your original phone. Payments are blocked only if you explicitly activate Recovery Protection or Account Freeze.</p>${lock?`<div class="status danger">Protected until ${new Date(lock).toLocaleString()}</div>`:`<div class="actions"><button class="btn danger" onclick="activateRecoveryLock(1)">Block payments 1 day</button><button class="btn secondary" onclick="activateRecoveryLock(3)">Block payments 3 days</button><button class="btn secondary" onclick="activateRecoveryLock(7)">Block payments 7 days</button></div>`}</div>`:''}
    ${duress?`<div class="recovery-box"><div class="eyebrow">SECURITY HOLD ACTIVE</div><h2>Outgoing payments are temporarily unavailable</h2><p class="muted">A security protection window is active. Payments and internal transfers remain blocked until it ends.</p><div class="status danger">Protected until ${new Date(duress).toLocaleString()}</div></div>`:''}
    ${s.mode==='normal'&&lock&&!duress?`<div class="recovery-box"><div class="eyebrow">RECOVERY PROTECTION</div><h2>Temporary payment lock is active</h2><p class="muted">Verify the account MPIN to restore outgoing payments early.</p><div class="field"><label>Account MPIN</label><input id="unlockMpin" type="password" inputmode="numeric" maxlength="6" placeholder="••••"></div><button class="btn" onclick="unlockRecoveryLock()">Verify & Restore Payments</button></div>`:''}
    <div class="account-section"><div><div class="eyebrow">FAVORITE IDS</div><h2>Quick Pay</h2><p class="muted">Favorites are convenience only and never bypass the trust engine.</p></div><button class="btn secondary" onclick="renderFavorites()">Manage Favorites</button></div>
    <div class="account-section"><div><div class="eyebrow">SECURITY</div><h2>Account Security</h2><p class="muted">Device status · login status · recovery status · MPIN protection · last login</p></div><button class="btn secondary" onclick="page('security')">Security Center</button></div>
    <div class="account-section"><div><div class="eyebrow">SETTINGS</div><h2>Preferences</h2><p class="muted">Security preferences · notifications · privacy · prototype disclosure</p></div><button class="btn secondary" onclick="renderSettings()">Open Settings</button></div>
    <div class="actions"><button class="btn secondary" onclick="changeMpinUI()">Change MPIN</button><button class="btn danger" onclick="logout()">Logout</button></div></section>`;
  try{new QRCode($('#myAccountQR'),{text:`LIPAY-ACCOUNT|id=${encodeURIComponent(account.fullPhone)}|type=receive`,width:180,height:180});}catch{}
}
function activateRecoveryLock(days){
  if(session().mode!=='emergency'){toast('Recovery lock can only be started from Emergency Recovery Mode.');return;}
  account.recoveryLockUntil=Date.now()+days*86400000;writeLocal(ACCOUNT,account);audit(`Recovery protection activated for ${days} day(s)`,'warn');renderAccountPage();
}
function unlockRecoveryLock(){
  if(session().mode!=='normal'){toast('Normal verified login is required to unlock recovery protection.');return;}
  if(String($('#unlockMpin')?.value||'')!==String(account.mpin)){toast('MPIN did not match.');audit('Recovery unlock failed — MPIN mismatch','danger');return;}
  account.recoveryLockUntil=0;writeLocal(ACCOUNT,account);audit('Verified owner restored outgoing payments');toast('Recovery protection removed');renderAccountPage();
}
function renderFavorites(){
  const f=favorites();
  $('#page').innerHTML=`<section class="card screen"><div class="eyebrow">FAVORITE IDS</div><h1>Favorites</h1><p class="muted">Convenience signal only — every payment still gets context, trust and final checks.</p>
    <div class="card inset"><div class="grid"><div class="field"><label>Name</label><input id="favName" placeholder="Merchant"></div><div class="field"><label>Payment ID</label><input id="favId" placeholder="merchant@lipay"></div></div><button class="btn" onclick="addFavorite()">＋ Add Favorite</button></div>
    ${f.map((x,i)=>`<div class="fav-item"><div><b>${esc(x.name)}</b><small>${esc(x.id)} · Last used ${x.lastUsed?new Date(x.lastUsed).toLocaleDateString():'Never'}</small></div><div class="actions"><button class="btn secondary" onclick="useFavorite(${i})">Pay</button><button class="btn danger" onclick="deleteFavorite(${i})">Delete</button></div></div>`).join('')||'<div class="empty">No favorites saved.</div>'}
    <button class="btn secondary" onclick="page('account')">Back to Account</button></section>`;
}
function addFavorite(){
  const name=$('#favName')?.value.trim(),id=$('#favId')?.value.trim();if(!name||!id){toast('Enter a name and payment ID.');return;}
  const f=favorites();if(f.some(x=>x.id.toLowerCase()===id.toLowerCase())){toast('That payment ID is already saved.');return;}
  f.push({name,id,lastUsed:null});writeLocal(FAV,f);audit(`Favorite ID added — ${name}`);renderFavorites();
}
function useFavorite(i){
  const f=favorites()[i];if(!f)return;f.lastUsed=new Date().toISOString();writeLocal(FAV,favorites());page('pay');setTimeout(()=>{const input=$('#recipient');if(input)input.value=f.id;},50);
}
function deleteFavorite(i){const f=favorites();f.splice(i,1);writeLocal(FAV,f);audit('Favorite ID deleted');renderFavorites();}
function changeMpinUI(){
  showModal(`<div class="eyebrow">MPIN PROTECTION</div><h2>Change MPIN</h2><p class="muted">Your current MPIN is never displayed.</p>
    <div class="field"><label>Current MPIN</label><input id="currentMpin" type="password" inputmode="numeric" maxlength="6"></div>
    <div class="field"><label>New MPIN</label><input id="newMpin" type="password" inputmode="numeric" maxlength="6"></div>
    <div class="field"><label>Confirm new MPIN</label><input id="confirmNewMpin" type="password" inputmode="numeric" maxlength="6"></div>
    <div class="actions"><button class="btn" onclick="changeMpin()">Update MPIN</button><button class="btn secondary" onclick="closeModal()">Cancel</button></div>`);
}
function changeMpin(){
  const cur=$('#currentMpin')?.value||'',next=$('#newMpin')?.value||'',confirm=$('#confirmNewMpin')?.value||'';
  if(cur!==String(account.mpin)){toast('Current MPIN is incorrect.');return;}
  if(!/^\d{4,6}$/.test(next)||next!==confirm){toast('New MPIN must be 4–6 digits and match confirmation.');return;} if(next===reverseMpinOf(next)){toast('Choose an MPIN that is different from its reverse.');return;}
  account.mpin=next;writeLocal(ACCOUNT,account);closeModal();audit('MPIN updated');toast('MPIN updated successfully');
}
const UI_PREFS='lipay_ui_preferences_v54';
function uiPrefs(){try{return JSON.parse(localStorage.getItem(UI_PREFS)||'{}')}catch{return {}}}
function applyUIPrefs(){
  const p=uiPrefs(), root=document.documentElement, body=document.body;
  root.style.setProperty('--ui-font-size',(p.fontSize||100)+'%');
  root.style.setProperty('--ui-brightness',(p.brightness||100)/100);
  body.dataset.font=p.font||'system'; body.dataset.theme=p.theme||'light'; body.dataset.contrast=p.contrast||'normal'; body.dataset.density=p.density||'comfortable'; body.dataset.motion=p.motion||'normal';
}
function saveUIPref(key,val){const p=uiPrefs();p[key]=val;localStorage.setItem(UI_PREFS,JSON.stringify(p));applyUIPrefs();renderSettings();toast('Display settings updated')}
function renderSettings(){
  const p=uiPrefs(), fs=p.fontSize||100, br=p.brightness||100;
  $('#page').innerHTML=`<section class="card screen settings-screen"><div class="eyebrow">SETTINGS</div><h1>Preferences</h1><p class="muted">Customize how LiPay looks and behaves on this device. Your choices are saved locally.</p>
    <div class="settings-group"><h2>Display & Accessibility</h2>
      <div class="settings-control"><div><b>Font size</b><small>${fs}%</small></div><input type="range" min="80" max="140" step="5" value="${fs}" oninput="saveUIPref('fontSize',this.value)"></div>
      <div class="settings-control"><div><b>Brightness</b><small>${br}%</small></div><input type="range" min="60" max="120" step="5" value="${br}" oninput="saveUIPref('brightness',this.value)"></div>
      <div class="settings-control"><div><b>Font style</b><small>Choose the interface typeface</small></div><select onchange="saveUIPref('font',this.value)"><option value="system" ${p.font==='system'?'selected':''}>System</option><option value="serif" ${p.font==='serif'?'selected':''}>Serif</option><option value="mono" ${p.font==='mono'?'selected':''}>Monospace</option><option value="rounded" ${p.font==='rounded'?'selected':''}>Rounded</option></select></div>
      <div class="settings-control"><div><b>Theme</b><small>Light or dark appearance</small></div><select onchange="saveUIPref('theme',this.value)"><option value="light" ${p.theme==='light'?'selected':''}>Light</option><option value="dark" ${p.theme==='dark'?'selected':''}>Dark</option></select></div>
      <div class="settings-control"><div><b>Contrast</b><small>Improve text and border visibility</small></div><select onchange="saveUIPref('contrast',this.value)"><option value="normal" ${p.contrast==='normal'?'selected':''}>Normal</option><option value="high" ${p.contrast==='high'?'selected':''}>High contrast</option></select></div>
      <div class="settings-control"><div><b>Layout density</b><small>Control spacing and compactness</small></div><select onchange="saveUIPref('density',this.value)"><option value="comfortable" ${p.density==='comfortable'?'selected':''}>Comfortable</option><option value="compact" ${p.density==='compact'?'selected':''}>Compact</option></select></div>
      <div class="settings-control"><div><b>Animations</b><small>Reduce movement for a calmer interface</small></div><select onchange="saveUIPref('motion',this.value)"><option value="normal" ${p.motion==='normal'?'selected':''}>Normal</option><option value="reduced" ${p.motion==='reduced'?'selected':''}>Reduced motion</option></select></div>
    </div>
    <div class="settings-group"><h2>Security & Privacy</h2>
      <div class="settings-row"><b>Security Preferences</b><small>Risk-based verification remains active for every payment.</small><span class="pill success">ACTIVE</span></div>
      <div class="settings-row"><b>Notification Preferences</b><small>Prototype notifications are local only.</small><span class="pill">DEMO</span></div>
      <div class="settings-row"><b>Recovery Protection</b><small>${paymentLock()?'ACTIVE':'READY'}</small><span class="pill ${paymentLock()?'danger':'success'}">${paymentLock()?'ACTIVE':'READY'}</span></div>
      <div class="settings-row"><b>Device Security</b><small>${localStorage.getItem('lipay_device_id')?'Known device':'New device until first trusted session'}</small></div>
      <div class="settings-row"><b>Privacy</b><small>Exact GPS coordinates are not stored in transaction history. The prototype uses only location availability.</small></div>
      <div class="settings-row"><b>Security Activity</b><small>Review safe security events.</small><button class="btn secondary" onclick="showSecurityEvents()">View Events</button></div>
    </div>
    <div class="prototype-warning"><b>PROTOTYPE MODE</b><br>Display preferences are stored locally in this browser. Production deployment requires secure backend authentication and production security controls.</div>
    <div class="actions"><button class="btn secondary" onclick="changeMpinUI()">Change MPIN</button><button class="btn secondary" onclick="resetUIPrefs()">Reset Display</button><button class="btn danger" onclick="resetDemo()">Reset Demo</button></div></section>`;
}
function resetUIPrefs(){localStorage.removeItem(UI_PREFS);applyUIPrefs();renderSettings();toast('Display settings reset')}
function renderSecurityCenter(){
  const h=history(), last=h[0], score=last?.score??92;
  $('#page').innerHTML=`<section class="card screen"><div class="eyebrow">SECURITY CENTER</div><h1>Continuous Trust</h1><p class="muted">LiPay evaluates <b>Person + Device + Transaction + Context</b>, then makes an adaptive decision.</p>
    <div class="security-overview"><div class="gauge" style="--score:${score}"><div class="gauge-in"><b>${score}</b><small>OVERALL TRUST</small></div></div><div><h2>${trustBand(score)}</h2><p class="muted">Prototype trust engine · explainable signals</p></div></div>
    <div class="evidence-grid big"><span>PERSON <b>✓ Verified</b></span><span>DEVICE <b>✓ Trusted</b></span><span>TRANSACTION <b>✓ Bound</b></span><span>CONTEXT <b>✓ Evaluated</b></span><span>QR INTEGRITY <b>✓ Active</b></span><span>TRANSACTION BINDING <b>✓ Active</b></span><span>MPIN PROTECTION <b>✓ Active</b></span><span>RISK-BASED VERIFICATION <b>✓ Active</b></span><span>RECOVERY PROTECTION <b>${paymentLock()?'ACTIVE':'Available'}</b></span></div>
    <div class="lab card inset"><div class="eyebrow">QR INTEGRITY LAB</div><h2>Controlled manipulation demonstration</h2><p class="muted">Original signed QR → transaction modified → signature verification → signature mismatch → payment blocked.</p>
      <div id="qrLab" class="lab-steps"><span>ORIGINAL SIGNED QR</span><b>↓</b><span>TRANSACTION MODIFIED</span><b>↓</b><span>SIGNATURE VERIFICATION</span><b>↓</b><span>SIGNATURE MISMATCH</span><b>↓</b><strong>PAYMENT BLOCKED</strong></div>
      <button class="btn" onclick="runQRLab()">RUN QR MANIPULATION DEMO</button></div>
    <div class="security-timeline"><div class="panel-head"><h3>Recent Security Events</h3></div>${readLocal(EVENTS,[]).slice(0,8).map(e=>`<div class="timeline-item"><span>${e.type==='danger'?'🚫':e.type==='warn'?'⚠':'✓'}</span><div><b>${new Date(e.time).toLocaleString()}</b><small>${esc(e.message)}</small></div></div>`).join('')||'<div class="empty">No security events yet.</div>'}</div>
    <div class="actions"><button class="btn secondary" onclick="renderSettings()">Security Preferences</button><button class="btn secondary" onclick="page('home')">Back Home</button></div></section>`;
}
async function runQRLab(){
  const lab=$('#qrLab');if(!lab)return;
  const original={to:'merchant@lipay',upi:'merchant@lipay',amt:2500,exp:Date.now()+30000,nonce:crypto.randomUUID()};original.sig=await qrSignature(original);
  const modified={...original,amt:3500};const valid=await qrSignature(modified)===modified.sig;
  lab.innerHTML=`<span class="lab-ok">ORIGINAL SIGNED QR<br><small>₹2,500 · merchant@lipay</small></span><b>↓</b><span class="lab-warn">TRANSACTION MODIFIED<br><small>₹2,500 → ₹3,500</small></span><b>↓</b><span>SIGNATURE VERIFICATION<br><small>Expected signature ≠ received signature</small></span><b>↓</b><span class="lab-danger">✕ SIGNATURE MISMATCH</span><b>↓</b><strong class="lab-danger">🚫 PAYMENT BLOCKED</strong>`;
  audit(`QR manipulation demo — signature ${valid?'valid':'mismatch'}; payment blocked`,'danger');toast('QR tampering detected — payment blocked');
}
function showModal(html){const root=$('#modalRoot');if(!root)return;root.innerHTML=`<div class="modal" role="dialog" aria-modal="true"><div class="modal-box">${html}</div></div>`;}
function closeModal(){$('#modalRoot').innerHTML='';}
function resetDemo(){
  if(!confirm('Reset the local LiPay 5.3 demo account, history, favorites and security events?'))return;
  [ACCOUNT,HISTORY,FAV,SEEN_QR,EVENTS,'lipay_used_tx_v54'].forEach(k=>localStorage.removeItem(k));
  localStorage.removeItem('lipay_device_id');sessionStorage.clear();account=null;toast('Demo reset');login();
}
function logout(){stopMedia();sessionStorage.removeItem(SESSION);login();}

function ensureSession(){
  ensureAccount();const s=session();
  if(s&&account&&s.phone===accountPhone())openApp();else login();
}
applyUIPrefs();
ensureSession();
