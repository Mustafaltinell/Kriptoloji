

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Tuple, Dict, Any



def caesar_encrypt(text: str, shift: int) -> str:
    res = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            res.append(ch)
    return "".join(res)

def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)

def _vig_shift(c):
    return ord(c.upper()) - ord('A')

def vigenere_encrypt(text: str, key: str) -> str:
    key = "".join([k for k in key if k.isalpha()])
    if not key:
        raise ValueError("Vigenère için anahtar harf olmali.")
    res, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            s = _vig_shift(key[j % len(key)])
            res.append(chr((ord(ch) - base + s) % 26 + base))
            j += 1
        else:
            res.append(ch)
    return "".join(res)

def vigenere_decrypt(text: str, key: str) -> str:
    key = "".join([k for k in key if k.isalpha()])
    if not key:
        raise ValueError("Vigenère için anahtar harf olmali.")
    res, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            s = _vig_shift(key[j % len(key)])
            res.append(chr((ord(ch) - base - s) % 26 + base))
            j += 1
        else:
            res.append(ch)
    return "".join(res)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def normalize_key_bytes(key_str: str, nbytes: int) -> bytes:
    """Kullanıcıdan gelen anahtarı UTF-8'e çevirip nbyte'a sabitler.

    - Kısa ise 0x00 ile sağdan pad
    - Uzun ise truncate

    AES: 16 byte, DES: 8 byte.
    """
    if key_str is None:
        key_str = ""
    b = key_str.encode("utf-8")
    if len(b) == nbytes:
        return b
    if len(b) < nbytes:
        return b + (b"\x00" * (nbytes - len(b)))
    return b[:nbytes]


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or (len(data) % block_size) != 0:
        raise ValueError("Geçersiz padding/paket boyutu")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Geçersiz padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Geçersiz padding")
    return data[:-pad_len]


def aes128_encrypt_lib(plaintext: str, key_str: str) -> str:
    """AES-128-CBC: çıktı Base64( IV || CIPHERTEXT )."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    key = normalize_key_bytes(key_str, 16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = plaintext.encode("utf-8")
    ct = cipher.encrypt(pkcs7_pad(pt, 16))
    return _b64e(iv + ct)


def aes128_decrypt_lib(b64_iv_ct: str, key_str: str) -> str:
    try:
        from Crypto.Cipher import AES
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    raw = _b64d(b64_iv_ct)
    if len(raw) < 16:
        raise ValueError("Geçersiz AES paket")
    key = normalize_key_bytes(key_str, 16)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = pkcs7_unpad(cipher.decrypt(ct), 16)
    return pt.decode("utf-8", errors="replace")


def des_encrypt_lib(plaintext: str, key_str: str) -> str:
    """DES-CBC: çıktı Base64( IV(8) || CIPHERTEXT )."""
    try:
        from Crypto.Cipher import DES
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    key = normalize_key_bytes(key_str, 8)
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = plaintext.encode("utf-8")
    ct = cipher.encrypt(pkcs7_pad(pt, 8))
    return _b64e(iv + ct)


def des_decrypt_lib(b64_iv_ct: str, key_str: str) -> str:
    try:
        from Crypto.Cipher import DES
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    raw = _b64d(b64_iv_ct)
    if len(raw) < 8:
        raise ValueError("Geçersiz DES paket")
    key = normalize_key_bytes(key_str, 8)
    iv, ct = raw[:8], raw[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = pkcs7_unpad(cipher.decrypt(ct), 8)
    return pt.decode("utf-8", errors="replace")


def rsa_generate_keypair(bits: int = 2048) -> Tuple[str, str]:
    """PEM formatında (public_pem, private_pem) döndürür."""
    try:
        from Crypto.PublicKey import RSA
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    key = RSA.generate(bits)
    private_pem = key.export_key().decode("ascii")
    public_pem = key.publickey().export_key().decode("ascii")
    return public_pem, private_pem


def rsa_encrypt_lib(plaintext: str, public_pem: str) -> str:
    """RSA-OAEP: çıktı Base64(ciphertext)."""
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    ct = cipher.encrypt(plaintext.encode("utf-8"))
    return _b64e(ct)


def rsa_decrypt_lib(b64_ciphertext: str, private_pem: str) -> str:
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    pt = cipher.decrypt(_b64d(b64_ciphertext))
    return pt.decode("utf-8", errors="replace")


_RSA_PUBLIC_PEM: str | None = None
_RSA_PRIVATE_PEM: str | None = None


def _load_or_create_server_rsa_keypair() -> Tuple[str, str]:
    """Uygulama açılırken bir kere çağrılır.

    İstersen anahtarları kalıcı yapmak için RSA_KEYS_DIR ortam değişkeni ver:
      - <RSA_KEYS_DIR>/rsa_public.pem
      - <RSA_KEYS_DIR>/rsa_private.pem
    """
    global _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM
    if _RSA_PUBLIC_PEM and _RSA_PRIVATE_PEM:
        return _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM

    key_dir = os.environ.get("RSA_KEYS_DIR")
    pub_path = os.path.join(key_dir, "rsa_public.pem") if key_dir else None
    priv_path = os.path.join(key_dir, "rsa_private.pem") if key_dir else None

    if pub_path and priv_path and os.path.exists(pub_path) and os.path.exists(priv_path):
        _RSA_PUBLIC_PEM = open(pub_path, "r", encoding="utf-8").read()
        _RSA_PRIVATE_PEM = open(priv_path, "r", encoding="utf-8").read()
        return _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM

    pub, priv = rsa_generate_keypair(2048)
    _RSA_PUBLIC_PEM, _RSA_PRIVATE_PEM = pub, priv

    if pub_path and priv_path:
        os.makedirs(key_dir, exist_ok=True)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(pub)
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(priv)

    return pub, priv



_load_or_create_server_rsa_keypair()


def rsa_public_pem() -> str:
    """Server'ın public key'i (PEM)."""
    return _RSA_PUBLIC_PEM or ""


def rsa_encrypt_oaep(plaintext: str) -> str:
    """Server public key ile RSA-OAEP şifrele (Base64)."""
    pub, _ = _load_or_create_server_rsa_keypair()
    return rsa_encrypt_lib(plaintext, pub)


def rsa_decrypt_oaep(b64_ciphertext: str) -> str:
    """Server private key ile RSA-OAEP çöz (Base64 -> text)."""
    _, priv = _load_or_create_server_rsa_keypair()
    return rsa_decrypt_lib(b64_ciphertext, priv)


def hybrid_rsa_aes_encrypt(plaintext: str, server_public_pem: str | None = None) -> str:
    """RSA ile rastgele AES anahtarını şifreler, mesajı AES ile şifreler.

    Çıktı JSON string:
    {
      "alg":"RSA+AES",
      "ek":"..." ,   # RSA-OAEP ile şifrelenmiş AES key (Base64)
      "ct":"..."    # AES-128-CBC Base64(IV||CT)
    }
    """
    try:
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    if server_public_pem is None:
        server_public_pem = rsa_public_pem()

    session_key = get_random_bytes(16)

    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    iv = get_random_bytes(16)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext.encode("utf-8"), 16))
    aes_blob = _b64e(iv + ct)


    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    pub = RSA.import_key(server_public_pem)
    rsa_cipher = PKCS1_OAEP.new(pub)
    ek = _b64e(rsa_cipher.encrypt(session_key))

    return json.dumps({"alg": "RSA+AES", "ek": ek, "ct": aes_blob}, ensure_ascii=False)


def hybrid_rsa_aes_decrypt(package_json: str, server_private_pem: str | None = None) -> str:
    try:
        obj = json.loads(package_json)
    except Exception:
        raise ValueError("Hybrid paket JSON değil")

    if obj.get("alg") != "RSA+AES":
        raise ValueError("Hybrid paket alg uyumsuz")

    ek_b64 = obj.get("ek")
    ct_b64 = obj.get("ct")
    if not ek_b64 or not ct_b64:
        raise ValueError("Hybrid paket eksik")

    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP, AES
    except Exception as e:
        raise ImportError("PyCryptodome gerekli: pip install pycryptodome") from e

    if server_private_pem is None:
        _, server_private_pem = _load_or_create_server_rsa_keypair()

    priv = RSA.import_key(server_private_pem)
    rsa_cipher = PKCS1_OAEP.new(priv)
    session_key = rsa_cipher.decrypt(_b64d(ek_b64))

    raw = _b64d(ct_b64)
    if len(raw) < 16:
        raise ValueError("AES blob bozuk")
    iv, ct = raw[:16], raw[16:]
    aes = AES.new(session_key, AES.MODE_CBC, iv)
    pt = pkcs7_unpad(aes.decrypt(ct), 16)
    return pt.decode("utf-8", errors="replace")


_SBOX = bytes([(i * 29 + 71) % 256 for i in range(256)])
_INV_SBOX = bytearray(256)
for i, v in enumerate(_SBOX):
    _INV_SBOX[v] = i
_INV_SBOX = bytes(_INV_SBOX)


def _rotate_left(b: bytes, n: int) -> bytes:
    n %= len(b)
    return b[n:] + b[:n]


def _rotate_right(b: bytes, n: int) -> bytes:
    n %= len(b)
    return b[-n:] + b[:-n]


def _miniaes_round_key(master_key: bytes, r: int) -> bytes:
   
    k = bytearray(_rotate_left(master_key, r))
    for i in range(len(k)):
        k[i] ^= (17 * r + i) & 0xFF
    return bytes(k)


def miniaes_encrypt_manual(plaintext: str, key_str: str, rounds: int = 4) -> str:
    """16-byte bloklu oyuncak şifre.

    - ECB benzeri çalışır (IV yok) -> Wireshark'ta desen bile görünebilir.
    - Eğitim için: SubBytes(SBOX), Permutation(rotate), AddRoundKey(XOR)

    Çıktı: Base64(ciphertext_bytes)
    """
    key = normalize_key_bytes(key_str, 16)
    data = pkcs7_pad(plaintext.encode("utf-8"), 16)

    out = bytearray()
    for off in range(0, len(data), 16):
        block = bytes(data[off:off+16])
        state = block
        for r in range(1, rounds + 1):
            rk = _miniaes_round_key(key, r)
          
            state = bytes(_SBOX[b] for b in state)
       
            state = _rotate_left(state, r)
      
            state = bytes((state[i] ^ rk[i]) for i in range(16))
        out.extend(state)

    return _b64e(bytes(out))


def miniaes_decrypt_manual(b64_ciphertext: str, key_str: str, rounds: int = 4) -> str:
    key = normalize_key_bytes(key_str, 16)
    data = _b64d(b64_ciphertext)
    if len(data) % 16 != 0:
        raise ValueError("MiniAES ciphertext blok boyutuna uymuyor")

    out = bytearray()
    for off in range(0, len(data), 16):
        state = bytes(data[off:off+16])
        for r in range(rounds, 0, -1):
            rk = _miniaes_round_key(key, r)
            # inverse AddRoundKey
            state = bytes((state[i] ^ rk[i]) for i in range(16))
            # inverse Permutation
            state = _rotate_right(state, r)
            # inverse SubBytes
            state = bytes(_INV_SBOX[b] for b in state)
        out.extend(state)

    pt = pkcs7_unpad(bytes(out), 16)
    return pt.decode("utf-8", errors="replace")
