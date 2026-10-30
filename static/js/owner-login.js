document.getElementById('loginForm').addEventListener('submit',async e=>{
 e.preventDefault();
 const button=document.getElementById('submit');
 const message=document.getElementById('message');
 button.disabled=true;
 message.textContent='Signing in...';
 try{
  const r=await fetch('/api/owner/login',{
   method:'POST',
   headers:{'Content-Type':'application/json'},
   credentials:'same-origin',
   body:JSON.stringify({
    email:document.getElementById('email').value.trim(),
    password:document.getElementById('password').value
   })
  });
  const d=await r.json();
  if(!r.ok) throw new Error(d.error||'Owner login failed.');
  location.href='/owner-dashboard';
 }catch(err){
  message.textContent=err.message||'Unable to sign in. Check your connection.';
 }finally{
  button.disabled=false;
 }
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .catch(error => console.error('Service worker registration failed:', error));
  });
}
