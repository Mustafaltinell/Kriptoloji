from flask import Flask, render_template, request, jsonify, url_for, redirect

from algorithms import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    aes128_encrypt_lib, aes128_decrypt_lib,
    des_encrypt_lib, des_decrypt_lib,
    miniaes_encrypt_manual, miniaes_decrypt_manual,
    rsa_public_pem, rsa_encrypt_oaep, rsa_decrypt_oaep,
    hybrid_rsa_aes_encrypt, hybrid_rsa_aes_decrypt,
)

import threading, webbrowser, os

app = Flask(__name__)

INBOX = []  


@app.get("/")
def home():
    return redirect(url_for("client_page"))


@app.get("/client")
def client_page():
    return render_template("client.html")


@app.get("/server")
def server_page():
    return render_template("server.html")


def _handle_crypto(method: str, key, message: str, decrypt: bool = False):
    m = (method or "").lower()

    if m.startswith("caesar"):
        try:
            s = int(key)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Caesar için anahtar sayi olmali (örn. 3)."}
        res = caesar_decrypt(message, s) if decrypt else caesar_encrypt(message, s)
        return {"ok": True, "result": res}

    if m.startswith("vigen"):
        if not isinstance(key, str) or not key.strip():
            return {"ok": False, "error": "Vigenère için harfli bir anahtar verin (örn. LEMON)."}
        try:
            res = vigenere_decrypt(message, key) if decrypt else vigenere_encrypt(message, key)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "result": res}

    if m in ("aes", "aes-128", "aes-lib"):
        if not isinstance(key, str) or not key:
            return {"ok": False, "error": "AES için anahtar gerekli (16 byte)."}
        try:
            res = aes128_decrypt_lib(message, key) if decrypt else aes128_encrypt_lib(message, key)
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"AES hata: {e}"}

    if m in ("des", "des-lib"):
        if not isinstance(key, str) or not key:
            return {"ok": False, "error": "DES için anahtar gerekli (8 byte)."}
        try:
            res = des_decrypt_lib(message, key) if decrypt else des_encrypt_lib(message, key)
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"DES hata: {e}"}

 
    if m in ("aes-manual", "miniaes", "manual-aes"):
        if not isinstance(key, str) or not key:
            return {"ok": False, "error": "Manuel MiniAES için anahtar gerekli (16 byte önerilir)."}
        try:
            res = miniaes_decrypt_manual(message, key) if decrypt else miniaes_encrypt_manual(message, key)
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"MiniAES hata: {e}"}


    if m in ("rsa", "rsa-oaep"):
        try:
            if decrypt:
                res = rsa_decrypt_oaep(message)
            else:
                res = rsa_encrypt_oaep(message)
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"RSA hata: {e}"}

    if m in ("rsa-aes", "hybrid", "hybrid-rsa-aes"):
        try:
            if decrypt:
                res = hybrid_rsa_aes_decrypt(message)
            else:
                res = hybrid_rsa_aes_encrypt(message)
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"Hybrid hata: {e}"}

    return {"ok": False, "error": "Desteklenmeyen yöntem."}


@app.post("/api/encrypt")
def api_encrypt():
    data = request.get_json(force=True, silent=True) or {}
    out = _handle_crypto(data.get("method"), data.get("key"), data.get("message", ""), decrypt=False)
    return (jsonify(out), 200 if out.get("ok") else 400)


@app.post("/api/decrypt")
def api_decrypt():
    data = request.get_json(force=True, silent=True) or {}
    out = _handle_crypto(data.get("method"), data.get("key"), data.get("message", ""), decrypt=True)
    return (jsonify(out), 200 if out.get("ok") else 400)


@app.get("/api/rsa/public")
def api_rsa_public():
    return jsonify({"ok": True, "public_pem": rsa_public_pem()})


@app.post("/api/server/receive")
def api_server_receive():
    """Client'ten gelen şifreli mesajı çözer ve INBOX'a yazar."""
    data = request.get_json(force=True, silent=True) or {}

    method = data.get("method")
    key = data.get("key")
    ciphertext = data.get("ciphertext", "")

   
    out = _handle_crypto(method, key, ciphertext, decrypt=True)
    if out.get("ok"):
        INBOX.append({
            "method": method,
            "ciphertext": ciphertext,
            "plaintext": out.get("result"),
        })
    return (jsonify(out), 200 if out.get("ok") else 400)


@app.get("/api/server/inbox")
def api_server_inbox():
    # sadece son 10 mesaj
    return jsonify({"ok": True, "items": INBOX[-10:]})


def open_browser():
    default_page = os.environ.get("START_PAGE", "CLIENT").upper()
    path = "/server" if default_page.startswith("S") else "/client"
    webbrowser.open(f"http://127.0.0.1:5000{path}")


if __name__ == "__main__":
    threading.Timer(1.0, open_browser).start()
    app.run(debug=True)
