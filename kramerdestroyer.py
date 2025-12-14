# kramer_payload_deobf.py
from binascii import unhexlify

STRINGS = "abcdefghijklmnopqrstuvwxyz0123456789"
KEY = 638238   

def dkyrie(text):
    out = ""
    for c in text:
        if c in STRINGS:
            i = STRINGS.index(c) + 1
            out += STRINGS[i] if i < len(STRINGS) else STRINGS[0]
        else:
            out += c
    return out

def unicode_decrypt(text):
    out = ""
    for c in text:
        out += "\n" if c == "ζ" else chr(ord(c) - KEY)
    return out

def main():
    from payload import _sparkle

    parts = _sparkle.split("/")
    encrypted = "".join(
        unhexlify(p).decode(errors="ignore")
        for p in parts
    )

    step1 = unicode_decrypt(encrypted)
    original = dkyrie(step1)

    with open("deobfuscated.py", "w", encoding="utf-8") as f:
        f.write(original)

    print("[+] Deobfuscation complete → deobfuscated.py")

if __name__ == "__main__":
    main()
