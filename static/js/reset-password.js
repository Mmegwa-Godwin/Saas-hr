const configElement=document.getElementById('reset-page-config');
const token=JSON.parse(configElement.textContent).token;
const form=document.getElementById('resetForm');
const message=document.getElementById('message');
if(!token){
    message.textContent='Reset token missing. Please request a new link.';
    form.querySelector('button').disabled=true;
}
form.addEventListener('submit',async function(event){
    event.preventDefault();
    const password=document.getElementById('password').value;
    const confirm=document.getElementById('confirm').value;
    const policyError = window.saasPasswordError(password);
    if(policyError){
        message.textContent = policyError;
        document.getElementById('password').focus();
        return;
    }
    if(password!==confirm){
        message.textContent='The passwords do not match.';
        document.getElementById('confirm').focus();
        return;
    }
    const button=form.querySelector('button');
    button.disabled=true;
    message.textContent='Resetting password...';
    try{
        const response=await fetch('/api/password/reset',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({token:token,password:password})
        });
        const data=await response.json();
        message.textContent=data.message||data.error||'Unable to reset password.';
        if(response.ok){
            form.style.display='none';
            const link=document.createElement('a');
            link.href='/';
            link.textContent='Go to login';
            message.appendChild(document.createElement('br'));
            message.appendChild(link);
        }
    }catch(error){
        message.textContent='Connection error. Please try again.';
    }finally{
        button.disabled=false;
    }
});
