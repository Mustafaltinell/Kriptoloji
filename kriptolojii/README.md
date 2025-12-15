# Kriptoloji Ödevi – İstemci/Sunucu (Flask)
- AES-128 (kütüphaneli)
- DES (kütüphaneli)
- RSA (kütüphaneli, OAEP)
- RSA ile anahtar dağıtımı + AES ile mesaj (Hybrid: RSA+AES)
- Kütüphanesiz sadeleştirilmiş MiniAES (eğitsel)

## Çalıştırma

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
# source .venv/bin/activate

pip install -r requirements.txt
python crypto_project\app.py
```

Tarayıcı:
- Client: http://127.0.0.1:5000/client
- Server: http://127.0.0.1:5000/server


