'''
Implementação em Python do S-AES (Simplified AES)
 - Tamanho do bloco: 16 bits (2x2 nibbles)
 - Tamanho da chave: 16 bits
 - Número de rodadas: 2
 - I/O no terminal: leitura de plaintext & chave, exibição de ciphertext em hex e Base64
 - Impressão de estados intermediários após cada função/rodada
 - Comparar S-AES vs AES oficial (NIST.FIPS.197)
'''

import sys
import base64

# S-Box de 4 bits (SubNibbles)
SBOX4 = [0x9,0x4,0xA,0xB, 0xD,0x1,0x8,0x5, 0x6,0x2,0x0,0x3, 0xC,0xE,0xF,0x7]

# Multiplicação em GF(2^4) com polinômio x^4 + x + 1 (0x13)
def gf4_mul(a: int, b: int) -> int:
    res = 0
    for i in range(4):
        if b & (1<<i):
            t = a
            # multiplicar por x^i
            for _ in range(i):
                # xtime em GF(2^4)
                t = ((t << 1) & 0xF) ^ (0x3 if (t & 0x8) else 0x0)
            res ^= t
    return res & 0xF

# Rotaciona pares de nibbles em um byte (para expansão de chave)
def rot_nib(w: int) -> int:
    return ((w << 4) & 0xF0) | ((w >> 4) & 0x0F)

# Substitui ambos nibbles de um byte usando SBOX4
def sub_nib_byte(w: int) -> int:
    return (SBOX4[(w >> 4) & 0xF] << 4) | SBOX4[w & 0xF]

# Expande chave de 16 bits em 3 chaves de rodada (16 bits cada)
def key_expansion(key: int) -> list[int]:
    RCON1, RCON2 = 0x80, 0x30
    w = [0]*6
    # separa chave inicial (2 bytes)
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    print(f"[KeyExpansion] w0=0x{w[0]:02X}, w1=0x{w[1]:02X}")
    # gera w2, w3
    w[2] = w[0] ^ (sub_nib_byte(rot_nib(w[1])) ^ RCON1)
    w[3] = w[2] ^ w[1]
    print(f"[KeyExpansion] w2=0x{w[2]:02X}, w3=0x{w[3]:02X}")
    # gera w4, w5
    w[4] = w[2] ^ (sub_nib_byte(rot_nib(w[3])) ^ RCON2)
    w[5] = w[4] ^ w[3]
    print(f"[KeyExpansion] w4=0x{w[4]:02X}, w5=0x{w[5]:02X}")
    # monta chaves de rodada
    round_keys = [((w[0] << 8) | w[1]), ((w[2] << 8) | w[3]), ((w[4] << 8) | w[5])]
    print(f"[RoundKeys] {['0x%04X'%rk for rk in round_keys]}")
    return round_keys

# Imprime matriz de estado (2x2 nibbles)
def print_state(s: list[list[int]], label: str) -> None:
    flat = [s[r][c] for r in range(2) for c in range(2)]
    print(f"{label}: [{','.join(f'0x{x:X}' for x in flat)}]")

# Encripta um bloco de 16 bits, mostrando estados intermediários
def encrypt_block(pt: int, rk: list[int]) -> int:
    # mapeia plaintext na matriz de estado
    s = [ [ (pt >> 12) & 0xF, (pt >> 4) & 0xF ],
          [ (pt >> 8) & 0xF, pt & 0xF ] ]
    print(f"\n[Block] PT=0x{pt:04X}")
    print_state(s, 'After load')
    # AddRoundKey0
    k = rk[0]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    print_state(s, 'After AddRoundKey0')
    # Rodada 1
    for r in range(2):
        for c in range(2): s[r][c] = SBOX4[s[r][c]]
    print_state(s, 'After SubNibbles R1')
    # ShiftRows (linha 1 rotaciona à esquerda)
    s[1][0], s[1][1] = s[1][1], s[1][0]
    print_state(s, 'After ShiftRows R1')
    # MixColumns
    for c in range(2):
        t0 = gf4_mul(1, s[0][c]) ^ gf4_mul(4, s[1][c])
        t1 = gf4_mul(4, s[0][c]) ^ gf4_mul(1, s[1][c])
        s[0][c], s[1][c] = t0, t1
    print_state(s, 'After MixColumns R1')
    # AddRoundKey1
    k = rk[1]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    print_state(s, 'After AddRoundKey1')
    # Rodada 2 final
    for r in range(2):
        for c in range(2): s[r][c] = SBOX4[s[r][c]]
    print_state(s, 'After SubNibbles R2')
    s[1][0], s[1][1] = s[1][1], s[1][0]
    print_state(s, 'After ShiftRows R2')
    # AddRoundKey2
    k = rk[2]
    s[0][0] ^= (k >> 12) & 0xF; s[1][0] ^= (k >> 8) & 0xF
    s[0][1] ^= (k >> 4) & 0xF;  s[1][1] ^= k & 0xF
    print_state(s, 'After AddRoundKey2')
    # reagrupa ciphertext
    ct = (s[0][0] << 12) | (s[1][0] << 8) | (s[0][1] << 4) | s[1][1]
    print(f"Cipher block=0x{ct:04X}")
    return ct

if __name__ == '__main__':
    # leitura de plaintext e chave
    msg = input('Enter message: ')
    key_hex = input('Enter 16-bit key (hex, 4 dígitos): ')
    try:
        key = int(key_hex, 16)
    except ValueError:
        print('Chave inválida!')
        sys.exit(1)
    # expande chaves
    round_keys = key_expansion(key)
    # prepara plaintext (em bytes) - se ímpar, acrescenta byte zero
    pb = msg.encode('utf-8')
    if len(pb) % 2:
        pb += b'\x00'
    ciphertext = []
    # encripta cada bloco de 2 bytes
    for i in range(0, len(pb), 2):
        block = (pb[i] << 8) | pb[i+1]
        ct = encrypt_block(block, round_keys)
        ciphertext.append((ct >> 8) & 0xFF)
        ciphertext.append(ct & 0xFF)
    # exibe resultados
    print('\nCiphertext (hex):', ''.join(f'{b:02x}' for b in ciphertext))
    print('Base64:', base64.b64encode(bytes(ciphertext)).decode())
