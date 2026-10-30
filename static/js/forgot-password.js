document.getElementById('forgotForm').addEventListener('submit',async function(event){
    event.preventDefault();
    const message=document.getElementById('message');
    const button=this.querySelector('button');
    button.disabled=true;
    message.textContent='Sending request...';
    try{
        const response=await fetch('/api/password/forgot',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({email:document.getElementById('email').value.trim()})
        });
        const data=await response.json();
        message.textContent=data.message||data.error||'If the account exists, reset instructions will be sent.';
    }catch(error){
        message.textContent='Unable to send the request. Check your connection and try again.';
    }finally{
        button.disabled=false;
    }
});
