function setKeyUI(container){
  const method = container.querySelector(".method-select").value.toLowerCase();
  const keyInput = container.querySelector(".key-input");
  const keyLabel = container.querySelector(".key-label");

  // Default
  keyInput.classList.remove("d-none");
  keyLabel.classList.remove("d-none");

  if(method.startsWith("caesar")){
    keyInput.type = "number";
    keyInput.placeholder = "3";
    keyInput.value = keyInput.value || 3;
    keyLabel.textContent = "🔑 Anahtar (Kaydırma Sayısı)";
  } else if(method.startsWith("vigen")){
    keyInput.type = "text";
    keyInput.placeholder = "LEMON";
    keyLabel.textContent = "🔑 Anahtar (Harfli Anahtar)";
  } else if(method.includes("aes-manual") || method.includes("miniaes") || method.includes("manual-aes")){
    keyInput.type = "text";
    keyInput.placeholder = "16 byte anahtar (örn: mysecretkey123456)";
    keyLabel.textContent = "🔑 Anahtar (MiniAES - 16 byte önerilir)";
  } else if(method.startsWith("aes")){
    keyInput.type = "text";
    keyInput.placeholder = "16 byte anahtar (örn: mysecretkey123456)";
    keyLabel.textContent = "🔑 Anahtar (AES-128 - 16 byte)";
  } else if(method.startsWith("des")){
    keyInput.type = "text";
    keyInput.placeholder = "8 byte anahtar (örn: 8bytekey)";
    keyLabel.textContent = "🔑 Anahtar (DES - 8 byte)";
  } else if(method.startsWith("rsa") || method.includes("hybrid")){
    // RSA/HYBRID'de kullanıcı anahtar girmez (server keypair kullanır)
    keyInput.value = "";
    keyInput.placeholder = "(RSA anahtarları sunucuda)";
    keyInput.classList.add("d-none");
    keyLabel.classList.add("d-none");
  } else {
    keyInput.type = "text";
    keyInput.placeholder = "Anahtar";
    keyLabel.textContent = "🔑 Anahtar";
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

function showAlert(el, text, kind){
  el.textContent = text;
  el.classList.remove("d-none","alert-primary","alert-success","alert-danger","alert-warning");
  el.classList.add(kind);
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
        showAlert(encOut, result, "alert-primary");
      }catch(err){
        showAlert(encOut, "Hata: " + err.message, "alert-danger");
      }
    });

    const copyEncBtn = document.getElementById("copy-encrypted");
    if(copyEncBtn){
      copyEncBtn.addEventListener("click", async ()=>{
        const text = document.getElementById("encrypt-result").textContent;
        if(text){ await navigator.clipboard.writeText(text); }
      });
    }

    // Encrypt + Send to server (ödevin istemci-sunucu kısmı)
    const sendBtn = document.getElementById("encrypt-send");
    if(sendBtn){
      sendBtn.addEventListener("click", async ()=>{
        encOut.classList.add("d-none");
        const fd = new FormData(encForm);
        const payload = { method: fd.get("method"), key: fd.get("key"), message: fd.get("message") };
        try{
          const {result} = await postJSON("/api/encrypt", payload);
          // ciphertext'i server'a yolla
          await postJSON("/api/server/receive", { method: payload.method, key: payload.key, ciphertext: result });
          showAlert(encOut, `Şifrelendi ve sunucuya gönderildi.\nCiphertext: ${result}`, "alert-success");
        }catch(err){
          showAlert(encOut, "Hata: " + err.message, "alert-danger");
        }
      });
    }
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
        showAlert(decOut, result, "alert-success");
      }catch(err){
        showAlert(decOut, "Hata: " + err.message, "alert-danger");
      }
    });

    const copyDecBtn = document.getElementById("copy-decrypted");
    if(copyDecBtn){
      copyDecBtn.addEventListener("click", async ()=>{
        const text = document.getElementById("decrypt-result").textContent;
        if(text){ await navigator.clipboard.writeText(text); }
      });
    }
  }

  // Server page polling
  const inboxEl = document.getElementById("server-inbox");
  if(inboxEl){
    const refresh = async ()=>{
      try{
        const res = await fetch("/api/server/inbox");
        const data = await res.json();
        if(!data.ok){ return; }
        const items = data.items || [];
        inboxEl.innerHTML = items.map((it, idx)=>{
          const m = (it.method||"").toUpperCase();
          const pt = (it.plaintext||"");
          const ct = (it.ciphertext||"");
          return `<div class="border rounded p-3 mb-2 bg-white">
              <div class="small text-muted">#${items.length-idx} · ${m}</div>
              <div class="mt-2"><b>Plaintext:</b> ${escapeHtml(pt)}</div>
              <div class="mt-2"><b>Ciphertext:</b> <code>${escapeHtml(ct)}</code></div>
            </div>`;
        }).join("") || `<div class="text-muted">Henüz mesaj yok. Client sayfasından 'Şifrele & Gönder' yap.</div>`;
      }catch(e){
        // sessiz geç
      }
    };
    refresh();
    setInterval(refresh, 1200);
  }
});

function escapeHtml(str){
  return String(str)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}
