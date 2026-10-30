let CID='';
const loginScreen=document.getElementById('loginScreen');

function showRegisterForm(){
    document.getElementById('loginForm').style.display='none';
    document.getElementById('registerForm').style.display='block';
    document.getElementById('registerMessage').innerText='';
}

function showLoginForm(){
    document.getElementById('registerForm').style.display='none';
    document.getElementById('loginForm').style.display='block';
    document.getElementById('registerMessage').innerText='';
}

async function registerCompany(){
    const name=document.getElementById('registerName').value.trim();
    const email=document.getElementById('registerEmail').value.trim();
    const password=document.getElementById('registerPass').value;
    const message=document.getElementById('registerMessage');

    if(!name||!email||!password){
        message.innerText='Please fill in all fields.';
        return;
    }
    const policyError = window.saasPasswordError(password);
    if(policyError){
        message.innerText = policyError;
        document.getElementById('registerPass').focus();
        return;
    }

    message.innerText='Creating company account...';
    try{
        const response=await fetch('/api/company/register',{
            method:'POST',
            credentials:'same-origin',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({name,email,password})
        });
        const result=await response.json();

        if(response.ok && result.company_id){
            document.getElementById('loginEmail').value=email;
            document.getElementById('loginPass').value=password;
            message.innerText='Company registered! Logging you in...';
            await doLogin();
        }else{
            message.innerText=result.error==='exists'
                ?'Registration failed. This email may already be registered.'
                :(result.error||'Registration failed. Please try again.');
        }
    }catch(error){
        message.innerText='Could not connect to the server. Please try again.';
    }
}

function showDashboard(company){
    CID=company.company_id;
    localStorage.setItem('cid',CID);
    document.getElementById('compId').innerText=CID;
    loginScreen.style.display='none';
    loadStats();
    loadStaff();
    loadSettings();
}

function showLogin(){
    CID='';
    localStorage.removeItem('cid');
    document.getElementById('compId').innerText='Not logged in';
    loginScreen.style.display='flex';
}

async function checkSession(){
    try{
        const r=await fetch('/api/session',{credentials:'same-origin'});
        if(!r.ok){
            showLogin();
            return;
        }
        const company=await r.json();
        if(company.authenticated && company.company_id){
            showDashboard(company);
        }else{
            showLogin();
        }
    }catch(error){
        showLogin();
    }
}

async function doLogin(){
    const email=document.getElementById('loginEmail').value.trim();
    const password=document.getElementById('loginPass').value;

    if(!email||!password){
        alert('Enter your email and password.');
        return;
    }

    try{
        const r=await fetch('/api/company/login',{
            method:'POST',
            credentials:'same-origin',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({email:email,password:password})
        });
        const j=await r.json();

        if(r.ok && j.company_id){
            showDashboard({company_id:j.company_id,name:j.name});
        }else{
            alert(j.error||'Login failed. Check your details.');
        }
    }catch(error){
        alert('Cannot connect. Please try again when the server is available.');
    }
}

async function doLogout(){
    if(!confirm('Logout?'))return;

    try{
        await fetch('/api/logout',{
            method:'POST',
            credentials:'same-origin'
        });
    }finally{
        localStorage.removeItem('cid');
        showLogin();
        location.reload();
    }
}

checkSession();

function navTo(t,el){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');if(el){document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));el.classList.add('active');}if(t=='home')loadStats();if(t=='staff'){loadOrgOptions();loadStaff();}if(t=='time')loadTimePage();if(t=='pay'){loadSettings();loadMySubs();}if(t=='settings'){loadSettings();loadAllSubs();}}
async function loadStats(){let r=await fetch('/api/stats/'+CID);let d=await r.json();document.getElementById('stStaff').innerText=d.staff;document.getElementById('stPresent').innerText=d.present;}
function staffEscape(value){
 return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function loadOrgOptions(){
 const message=document.getElementById('staffFormMessage');
 try{
  const [dr,br]=await Promise.all([fetch('/api/departments'),fetch('/api/branches')]);
  const departments=await dr.json();
  const branches=await br.json();
  if(!dr.ok||!br.ok)throw new Error(departments.error||branches.error||'Could not load departments and branches.');
  const deptSelect=document.getElementById('sdept');
  const branchSelect=document.getElementById('sbranch');
  const oldDept=deptSelect.value,oldBranch=branchSelect.value;
  const activeDepartments=departments.filter(d=>d.active);
  const activeBranches=branches.filter(b=>b.active);
  deptSelect.innerHTML='<option value="">Select a department</option>'+activeDepartments.map(d=>`<option value="${staffEscape(d.id)}">${staffEscape(d.name)}</option>`).join('');
  branchSelect.innerHTML='<option value="">No branch assigned</option>'+activeBranches.map(b=>`<option value="${staffEscape(b.id)}">${staffEscape(b.name)}</option>`).join('');
  if(activeDepartments.some(d=>d.id===oldDept))deptSelect.value=oldDept;
  if(activeBranches.some(b=>b.id===oldBranch))branchSelect.value=oldBranch;
  document.getElementById('departmentList').innerHTML=departments.map(d=>`<div class="list-item"><span>${staffEscape(d.name)}</span><span>${d.active?'Active':'Inactive'}</span></div>`).join('')||'<p>No departments yet.</p>';
  document.getElementById('branchList').innerHTML=branches.map(b=>`<div class="list-item"><div><b>${staffEscape(b.name)}</b><br><small>${staffEscape(b.address||'No address added')}</small></div><span>${b.active?'Active':'Inactive'}</span></div>`).join('')||'<p>No branches yet.</p>';
  if(message)message.textContent=activeDepartments.length?'':'Create a department below before adding an employee.';
 }catch(error){if(message)message.textContent=error.message;else console.error(error);}
}
async function createDepartment(){
 const input=document.getElementById('newDepartmentName');
 const name=input.value.trim();
 if(!name)return alert('Enter a department name.');
 try{
  const r=await fetch('/api/departments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  const d=await r.json();
  if(!r.ok)return alert(d.error||'Could not create department.');
  input.value='';
  await loadOrgOptions();
  document.getElementById('sdept').value=d.id;
  alert('Department created.');
 }catch(error){alert('Could not create department. Check your connection.');}
}
async function createBranch(){
 const name=document.getElementById('newBranchName').value.trim();
 const address=document.getElementById('newBranchAddress').value.trim();
 if(!name)return alert('Enter a branch or factory name.');
 try{
  const r=await fetch('/api/branches',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,address})});
  const d=await r.json();
  if(!r.ok)return alert(d.error||'Could not create branch.');
  document.getElementById('newBranchName').value='';
  document.getElementById('newBranchAddress').value='';
  await loadOrgOptions();
  document.getElementById('sbranch').value=d.id;
  alert('Branch created.');
 }catch(error){alert('Could not create branch. Check your connection.');}
}
async function addStaff(){
 const body={
  company_id:CID,
  name:document.getElementById('sname').value.trim(),
  email:document.getElementById('semail').value.trim(),
  role:document.getElementById('srole').value,
  department_id:document.getElementById('sdept').value,
  branch_id:document.getElementById('sbranch').value,
  job_title:document.getElementById('sjobtitle').value.trim(),
  password:document.getElementById('spass').value
 };
 const message=document.getElementById('staffFormMessage');
 if(!body.name||!body.email){message.textContent='Name and email are required.';return;}
 if(!body.department_id){message.textContent='Create and select a department first.';return;}
 const policyError=window.saasPasswordError(body.password);
 if(policyError){
  message.textContent=policyError;
  document.getElementById('spass').focus();
  return;
 }
 try{
  const r=await fetch('/api/staff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok){message.textContent=d.error||'Could not add employee.';return;}
  message.textContent='Employee added. Share the password securely.';
  document.getElementById('spass').value='';
  document.getElementById('sname').value='';
  document.getElementById('semail').value='';
  document.getElementById('sjobtitle').value='';
  await loadStaff();
  await loadStats();
 }catch(error){message.textContent='Could not add employee. Check your connection.';}
}
async function loadStaff(){
 const r=await fetch('/api/staff/'+encodeURIComponent(CID));
 const staff=await r.json();
 if(!r.ok){document.getElementById('staffList').textContent=staff.error||'Could not load employees.';return;}
 let html='';
 for(const u of staff){
  let status={status:'unknown'};
  try{status=await (await fetch('/api/attendance/status/'+encodeURIComponent(u.id))).json();}catch(e){}
  const btn=status.status==='not_in'?`<button class="btn btn-black btn-sm" onclick="doClockIn('${staffEscape(u.id)}')">In</button>`:status.status==='in'?`<button class="btn btn-ghost btn-sm" onclick="doClockOut('${staffEscape(u.id)}')">Out ${Math.round(status.distance||0)}m</button>`:status.status==='done'?`Done ${Math.round(status.distance||0)}m ✓`:'';
  const details=[u.job_title,u.department,u.branch_name].filter(Boolean).map(staffEscape).join(' · ');
  html+=`<div class="list-item"><div style="display:flex;gap:8px;align-items:center"><div class="avatar">${staffEscape((u.name||'?').charAt(0).toUpperCase())}</div><div><b>${staffEscape(u.name)}</b><br><small>${staffEscape(u.email||'')}<br>${details||'No assignment details'} · ${staffEscape(u.role)} · ${u.active?'Active':'Inactive'}</small></div></div>${btn}</div>`;
 }
 document.getElementById('staffList').innerHTML=html||'No employees yet.';
 document.getElementById('liveList').innerHTML=html;
}
async function loadTimePage(){let r=await fetch('/api/staff/'+CID);let staff=await r.json();let board='';for(let u of staff){let st=await (await fetch('/api/attendance/status/'+u.id)).json();let btn=st.status=='not_in'?`<button class="btn btn-black btn-sm" onclick="doClockIn('${u.id}')">IN</button>`:st.status=='in'?`<button class="btn btn-ghost btn-sm" onclick="doClockOut('${u.id}')">OUT</button>`:`✓`;board+=`<div class="list-item"><b>${u.name}</b> ${btn}</div>`;}document.getElementById('clockBoard').innerHTML=board;loadAtt();}
async function doClockIn(uid){navigator.geolocation.getCurrentPosition(async pos=>{let r=await fetch('/api/attendance/clock-in',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,user_id:uid,lat:pos.coords.latitude,lng:pos.coords.longitude,photo_hash:btoa(uid+Date.now()).slice(0,40)})});let j=await r.json();alert(j.msg);loadStaff();loadTimePage();loadStats();},()=>alert('Enable GPS'),{enableHighAccuracy:true});}
async function doClockOut(uid){let r=await fetch('/api/attendance/clock-out',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,user_id:uid})});let j=await r.json();alert(j.msg);loadStaff();loadTimePage();loadStats();}
async function loadAtt(){let r=await fetch('/api/attendance/'+CID);let d=await r.json();document.getElementById('attList').innerHTML=d.map(a=>`<div class="list-item"><b>${a.name}</b> ${a.date} ${Math.round(a.distance||0)}m</div>`).join('')||'None';}
async function loadSettings(){let r=await fetch('/api/settings');let d=await r.json();mpAccount.innerText=d.moniepoint_account||'-';mpName.innerText=d.moniepoint_name||'-';setAccount.value=d.moniepoint_account||'';setName.value=d.moniepoint_name||'';setLat.value=d.office_lat||6.5244;setLng.value=d.office_lng||3.3792;setRadius.value=d.office_radius||50;officeStatus.innerText=`Fence ${d.office_radius}m`;}
async function useMyLocation(){navigator.geolocation.getCurrentPosition(p=>{setLat.value=p.coords.latitude;setLng.value=p.coords.longitude;});}
async function saveOffice(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({office_lat:parseFloat(setLat.value),office_lng:parseFloat(setLng.value),office_radius:parseFloat(setRadius.value)})});alert('Saved');loadSettings();}
async function saveSettings(){await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:setAccount.value,name:setName.value})});alert('Saved');}
function openPay(p,a){curPlan=p;curAmount=a;mpAmount.innerText='₦'+a;payBox.style.display='block';}
async function submitProof(){await fetch('/api/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company_id:CID,plan:curPlan,amount:curAmount,proof:proof.value})});alert('Submitted');loadMySubs();}
async function loadMySubs(){let r=await fetch('/api/subscriptions/'+CID);let d=await r.json();mySubs.innerHTML=d.map(s=>`<div>${s.plan} ${s.status}</div>`).join('')||'None';}
async function loadAllSubs(){let r=await fetch('/api/subscriptions/all');let d=await r.json();allSubs.innerHTML=d.map(s=>`<div class="list-item"><b>${s.company_id}</b> <button class="btn btn-black btn-sm" onclick="approveSub('${s.id}')">Approve</button></div>`).join('')||'None';}
async function approveSub(id){await fetch('/api/subscriptions/approve/'+id,{method:'POST'});alert('Approved');loadAllSubs();}
