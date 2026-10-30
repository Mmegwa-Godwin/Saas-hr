const message=document.getElementById('message');
function cell(value){
 const td=document.createElement('td');
 td.textContent=value==null?'':String(value);
 return td;
}
function table(headers,rows){
 const t=document.createElement('table');
 const thead=document.createElement('thead');
 const hr=document.createElement('tr');
 headers.forEach(h=>{const th=document.createElement('th');th.textContent=h;hr.appendChild(th)});
 thead.appendChild(hr);t.appendChild(thead);
 const body=document.createElement('tbody');
 rows.forEach(row=>body.appendChild(row));
 t.appendChild(body);return t;
}
async function api(url,options={}){
 const method=String(options.method||'GET').toUpperCase();
 const headers={...(options.headers||{})};
 if(['POST','PUT','PATCH','DELETE'].includes(method)){
  const tokenResponse=await fetch('/api/csrf-token',{credentials:'same-origin'});
  const tokenData=await tokenResponse.json();
  headers['X-CSRF-Token']=tokenData.csrf_token;
 }
 const r=await fetch(url,{credentials:'same-origin',...options,headers});
 const d=await r.json();
 if(r.status===401){location.href='/owner-login';throw new Error('Owner session expired. Please sign in again.')}
 if(!r.ok)throw new Error(d.error||'Request failed.');
 return d;
}
async function loadCompanies(){
 const data=await api('/api/owner/companies');
 const rows=data.map(c=>{
  const tr=document.createElement('tr');
  [c.name,c.email,c.plan,c.created,c.operational_status||'active'].forEach(v=>tr.appendChild(cell(v)));
  const action=document.createElement('td');
  const select=document.createElement('select');
  [['active','Active'],['paused','Temporarily Paused'],['suspended','Suspended'],['closed','Closed']]
   .forEach(([value,label])=>{
    const option=document.createElement('option');
    option.value=value;option.textContent=label;select.appendChild(option);
   });
  select.value=c.operational_status||'active';
  const button=document.createElement('button');
  button.textContent='Save status';
  button.addEventListener('click',async()=>{
   const reason=prompt('Reason for this company status change:');
   if(reason===null)return;
   if(!reason.trim()){message.textContent='A reason is required.';return}
   button.disabled=true;
   try{
    await api('/api/owner/companies/'+encodeURIComponent(c.id)+'/status',{
     method:'PATCH',
     headers:{'Content-Type':'application/json'},
     body:JSON.stringify({status:select.value,reason:reason.trim()})
    });
    message.textContent='Company status updated.';
    await loadCompanies();
   }catch(e){message.textContent=e.message;button.disabled=false}
  });
  action.append(select,button);tr.appendChild(action);
  return tr;
 });
 const box=document.getElementById('companies');
 box.replaceChildren();
 if(!rows.length){box.textContent='No companies registered yet.';return}
 box.appendChild(table(['Company','Email','Plan','Created','Operational Status','Action'],rows));
}
async function loadSubscriptions(){
 const data=await api('/api/owner/subscriptions');
 const rows=data.map(s=>{
  const tr=document.createElement('tr');
  [s.company_name||s.company_id,s.plan,'₦'+Number(s.amount||0).toLocaleString(),s.status,s.created].forEach(v=>tr.appendChild(cell(v)));
  const action=document.createElement('td');
  if(String(s.status).toLowerCase()!=='approved' && String(s.status).toLowerCase()!=='active'){
   const button=document.createElement('button');
   button.textContent='Approve';
   button.addEventListener('click',async()=>{
    if(!confirm('Approve this subscription?'))return;
    button.disabled=true;
    try{
     await api('/api/owner/subscriptions/approve/'+encodeURIComponent(s.id),{method:'POST'});
     await loadSubscriptions();
     message.textContent='Subscription approved.';
    }catch(e){message.textContent=e.message;button.disabled=false}
   });
   action.appendChild(button);
  }else{
   action.textContent='—';
  }
  tr.appendChild(action);return tr;
 });
 const box=document.getElementById('subscriptions');
 box.replaceChildren();
 if(!rows.length){box.textContent='No subscriptions found.';return}
 box.appendChild(table(['Company','Plan','Amount','Status','Created','Action'],rows));
}
async function start(){
 try{
  const d=await api('/api/owner/session');
  document.getElementById('ownerEmail').textContent=d.email||'Owner';
  await Promise.all([loadCompanies(),loadSubscriptions()]);
  message.textContent='';
 }catch(e){message.textContent=e.message}
}
document.getElementById('logout').addEventListener('click',async()=>{
 try{await fetch('/api/owner/logout',{method:'POST',credentials:'same-origin'})}
 finally{location.href='/owner-login'}
});
start();

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .catch(error => console.error('Service worker registration failed:', error));
  });
}
