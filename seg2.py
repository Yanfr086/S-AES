'''
Implementação em Python do S-AES no modo ECB
 - Tamanho do bloco: 16 bits (2x2 nibbles)
 - Tamanho da chave: 16 bits
 - Número de rodadas: 2
 - Função auxiliar encrypt_saes_ecb(msg, key) retorna bytes do ciphertext
 - Exibe saída em Base64
 - Demonstra fraqueza do modo ECB: blocos idênticos geram ciphertexts idênticos
'''

import base64
from typing import List

# S-Box de 4 bits
SBOX4 = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7]

# Multiplicação em GF(2^4) com polinômio x^4 + x + 1
def gf4_mul(a: int, b: int) -> int:
    r = 0
    for i in range(4):
        if b & (1 << i):
            t = a
            for _ in range(i):
                t = ((t << 1) & 0xF) ^ (0x3 if (t & 0x8) else 0)
            r ^= t
    return r & 0xF

# Rotaciona pares de nibbles em um byte
def rot_nib(w: int) -> int:
    return ((w << 4) & 0xF0) | ((w >> 4) & 0x0F)

# Substitui nibbles de um byte usando SBOX4
def sub_nib_byte(w: int) -> int:
    return (SBOX4[(w >> 4) & 0xF] << 4) | SBOX4[w & 0xF]

# Expansão de chave de 16 bits em 3 chaves de rodada
def key_expansion(key: int) -> List[int]:
    RCON1, RCON2 = 0x80, 0x30
    w = [0] * 6
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    # gera w2, w3
    w[2] = w[0] ^ (sub_nib_byte(rot_nib(w[1])) ^ RCON1)
    w[3] = w[2] ^ w[1]
    # gera w4, w5
    w[4] = w[2] ^ (sub_nib_byte(rot_nib(w[3])) ^ RCON2)
    w[5] = w[4] ^ w[3]
    # monta chaves de rodada
    return [((w[0] << 8) | w[1]), ((w[2] << 8) | w[3]), ((w[4] << 8) | w[5])]

# Encripta um bloco de 16 bits
def encrypt_block(pt: int, rk: List[int]) -> int:
    # carrega texto claro na matriz 2x2
    s = [[(pt >> 12) & 0xF, (pt >> 4) & 0xF],
         [(pt >> 8) & 0xF, pt & 0xF]]
    # AddRoundKey0
    k = rk[0]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    # Rodada 1
    for r in range(2):
        for c in range(2): s[r][c] = SBOX4[s[r][c]]
    # ShiftRows
    s[1][0], s[1][1] = s[1][1], s[1][0]
    # MixColumns
    for c in range(2):
        t0 = gf4_mul(1, s[0][c]) ^ gf4_mul(4, s[1][c])
        t1 = gf4_mul(4, s[0][c]) ^ gf4_mul(1, s[1][c])
        s[0][c], s[1][c] = t0, t1
    # AddRoundKey1
    k = rk[1]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    # Rodada 2
    for r in range(2):
        for c in range(2): s[r][c] = SBOX4[s[r][c]]
    # ShiftRows
    s[1][0], s[1][1] = s[1][1], s[1][0]
    # AddRoundKey2
    k = rk[2]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    # reagrupa ciphertext
    return (s[0][0] << 12) | (s[1][0] << 8) | (s[0][1] << 4) | s[1][1]

# Função auxiliar de encriptação em modo ECB
def encrypt_saes_ecb(msg: str, key: int) -> bytes:
    rk = key_expansion(key)
    pb = msg.encode('utf-8')
    if len(pb) % 2:
        pb += b'\x00'
    ct_bytes = bytearray()
    for i in range(0, len(pb), 2):
        block = (pb[i] << 8) | pb[i+1]
        ct = encrypt_block(block, rk)
        ct_bytes.extend([(ct >> 8) & 0xFF, ct & 0xFF])
    return bytes(ct_bytes)

# Codificação Base64
def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')

if __name__ == '__main__':
    # Demonstração da fraqueza do ECB
    msg = 'TESTTEST'  # 4 bytes repetidos -> 2 blocos idênticos
    key = 0x3A94
    ct = encrypt_saes_ecb(msg, key)
    print(f"Plaintext: {msg}")
    print("Cipher (hex):", ''.join(f"{b:02x}" for b in ct))
    print("Cipher (Base64):", base64_encode(ct))
    print("Nota: blocos 0 e 2 são idênticos => ciphertexts correspondentes também são.")
