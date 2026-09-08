/* LiPay demo backend: static hosting + local duress-event logging only.
   It deliberately does not send SMS or contact police/emergency services. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const EVENTS = path.join(DATA_DIR, 'emergency-events.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, {recursive:true});
if (!fs.existsSync(EVENTS)) fs.writeFileSync(EVENTS, '[]');
const mime = {'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8'};
function send(res,status,body,type='text/plain; charset=utf-8'){res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store'});res.end(body)}
const server=http.createServer((req,res)=>{
  if(req.method==='POST' && req.url==='/api/security/duress-event'){
    let body=''; req.on('data',c=>{body+=c; if(body.length>100000) req.destroy()});
    req.on('end',()=>{try{const event=JSON.parse(body||'{}'); const events=JSON.parse(fs.readFileSync(EVENTS,'utf8')); events.unshift({...event,receivedAt:new Date().toISOString()}); fs.writeFileSync(EVENTS,JSON.stringify(events.slice(0,500),null,2)); send(res,202,JSON.stringify({ok:true,status:'queued-demo-backend'}),'application/json')}catch{send(res,400,JSON.stringify({ok:false}),'application/json')}});
    return;
  }
  if(req.method==='GET' && req.url==='/api/security/duress-events') return send(res,200,fs.readFileSync(EVENTS), 'application/json');
  if(req.method!=='GET' && req.method!=='HEAD') return send(res,405,'Method not allowed');
  let urlPath=decodeURIComponent(req.url.split('?')[0]); if(urlPath==='/') urlPath='/index.html';
  const file=path.resolve(ROOT,'.'+urlPath); if(!file.startsWith(ROOT)) return send(res,403,'Forbidden');
  fs.readFile(file,(err,data)=>{if(err)return send(res,404,'Not found'); send(res,200,data,mime[path.extname(file)]||'application/octet-stream')});
});
const port=process.env.PORT||8000; server.listen(port,()=>console.log(`LiPay demo running at http://localhost:${port}`));
