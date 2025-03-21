import random
with open("calc.bin", "rb") as f:
    data = f.read()
key = b'0x5A'  # 与代码中的 XOR_KEY 一致
encrypted = bytes(b ^ k for b, k in zip(data, key * len(data)))
with open("calc_encrypted.bin", "wb") as f:
    f.write(encrypted)