function setKeyUI(container){
  const method = container.querySelector(".method-select").value.toLowerCase();
  const keyInput = container.querySelector(".key-input");
  const keyLabel = container.querySelector(".key-label");
  if(method.startsWith("caesar")){
    keyInput.type = "number";
    keyInput.value = keyInput.value || 3;
    keyLabel.textContent = "🔑 Anahtar (Kaydırma Sayısı)";
  }else{ 
    keyInput.type = "text";
    keyInput.placeholder = "LEMON";
    keyLabel.textContent = "🔑 Anahtar (Harfli Anahtar)";
  }
}

async function postJSON(url, payload){
  const res = await fetch(url, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)
  });
  const data = await res.json().catch(()=>({ok:false,error:"Sunucudan geçersiz yanıt"}));
  if(!res.ok || !data.ok){ throw new Error(data.error || "İşlem başarısız"); }
  return data;
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".method-select").forEach(sel => {
    const pane = sel.closest(".p-4");
    setKeyUI(pane);
    sel.addEventListener("change", () => setKeyUI(pane));
  });

  const encForm = document.getElementById("encrypt-form");
  if(encForm){
    const encOut = document.getElementById("encrypt-result");
    encForm.addEventListener("submit", async (e)=>{
      e.preventDefault();
      encOut.classList.add("d-none");
      const fd = new FormData(encForm);
      const payload = { method: fd.get("method"), key: fd.get("key"), message: fd.get("message") };
      try{
        const {result} = await postJSON("/api/encrypt", payload);
        encOut.textContent = result;
        encOut.classList.remove("d-none");
        encOut.classList.remove("alert-danger");
        encOut.classList.add("alert-primary");
      }catch(err){
        encOut.textContent = "Hata: " + err.message;
        encOut.classList.remove("d-none");
        encOut.classList.remove("alert-primary");
        encOut.classList.add("alert-danger");
      }
    });
    document.getElementById("copy-encrypted").addEventListener("click", async ()=>{
      const text = document.getElementById("encrypt-result").textContent;
      if(text){ await navigator.clipboard.writeText(text); }
    });
  }

  const decForm = document.getElementById("decrypt-form");
  if(decForm){
    const decOut = document.getElementById("decrypt-result");
    decForm.addEventListener("submit", async (e)=>{
      e.preventDefault();
      decOut.classList.add("d-none");
      const fd = new FormData(decForm);
      const payload = { method: fd.get("method"), key: fd.get("key"), message: fd.get("message") };
      try{
        const {result} = await postJSON("/api/decrypt", payload);
        decOut.textContent = result;
        decOut.classList.remove("d-none");
        decOut.classList.remove("alert-danger");
        decOut.classList.add("alert-success");
      }catch(err){
        decOut.textContent = "Hata: " + err.message;
        decOut.classList.remove("d-none");
        decOut.classList.remove("alert-success");
        decOut.classList.add("alert-danger");
      }
    });
    document.getElementById("copy-decrypted").addEventListener("click", async ()=>{
      const text = document.getElementById("decrypt-result").textContent;
      if(text){ await navigator.clipboard.writeText(text); }
    });
  }
});
