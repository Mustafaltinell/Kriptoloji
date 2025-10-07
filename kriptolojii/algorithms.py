
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
