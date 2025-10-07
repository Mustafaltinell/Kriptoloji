
from flask import Flask, render_template, request, jsonify, url_for, redirect
from algorithms import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt
import threading, webbrowser, os

app = Flask(__name__)

@app.get("/")
def home():
    
    return redirect(url_for("client_page"))

@app.get("/client")
def client_page():
    return render_template("client.html")

@app.get("/server")
def server_page():
    return render_template("server.html")

def _handle(method: str, key, message: str, decrypt=False):
    m = (method or "").lower()
    if m.startswith("caesar"):
        try:
            s = int(key)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Caesar için anahtar sayi olmali (örn. 3)."}
        res = caesar_decrypt(message, s) if decrypt else caesar_encrypt(message, s)
        return {"ok": True, "result": res}
    elif m.startswith("vigen"):
        if not isinstance(key, str) or not key.strip():
            return {"ok": False, "error": "Vigenère için harfli bir anahtar verin (örn. LEMON)."}
        try:
            res = vigenere_decrypt(message, key) if decrypt else vigenere_encrypt(message, key)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "result": res}
    else:
        return {"ok": False, "error": "Desteklenmeyen yöntem."}

@app.post("/api/encrypt")
def api_encrypt():
    data = request.get_json(force=True, silent=True) or {}
    out = _handle(data.get("method"), data.get("key"), data.get("message",""), decrypt=False)
    return (jsonify(out), 200 if out.get("ok") else 400)

@app.post("/api/decrypt")
def api_decrypt():
    data = request.get_json(force=True, silent=True) or {}
    out = _handle(data.get("method"), data.get("key"), data.get("message",""), decrypt=True)
    return (jsonify(out), 200 if out.get("ok") else 400)

def open_browser():
    
    default_page = os.environ.get("START_PAGE", "CLIENT").upper()
    path = "/server" if default_page.startswith("S") else "/client"
    webbrowser.open(f"http://127.0.0.1:5000{path}")

if __name__ == "__main__":
    # Otomatik olarak tarayıcıyı aç (1 sn gecikmeyle)
    threading.Timer(1.0, open_browser).start()
    # debug=True geliştirme içindir; istersen port=5050 kullan
    app.run(debug=True)
