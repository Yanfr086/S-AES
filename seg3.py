from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode
import time

# ===========================
# PARÂMETROS FIXOS E ENTRADA
# ===========================

mensagem = "Segurança Computacional"
mensagem_bytes = mensagem.encode('utf-8')

# Chave AES de 128 bits (16 bytes)
chave = b'1234567890abcdef'

# Vetor de inicialização (IV) de 16 bytes para CBC, CFB, OFB
iv = b'abcdef1234567890'

# Nonce de 16 bytes para CTR
nonce = b'1234567890abcdef'

# =====================
# FUNÇÕES POR MODO AES
# =====================

def to_base64(data_bytes):
    return b64encode(data_bytes).decode('utf-8')

def aplicar_padding(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def aes_ecb(msg, chave):
    msg_padded = aplicar_padding(msg)
    start = time.time()
    cipher = Cipher(algorithms.AES(chave), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg_padded) + encryptor.finalize()
    end = time.time()
    return to_base64(ct), round(end - start, 6)

def aes_cbc(msg, chave, iv):
    msg_padded = aplicar_padding(msg)
    start = time.time()
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg_padded) + encryptor.finalize()
    end = time.time()
    return to_base64(ct), round(end - start, 6)

def aes_cfb(msg, chave, iv):
    start = time.time()
    cipher = Cipher(algorithms.AES(chave), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg) + encryptor.finalize()
    end = time.time()
    return to_base64(ct), round(end - start, 6)

def aes_ofb(msg, chave, iv):
    start = time.time()
    cipher = Cipher(algorithms.AES(chave), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg) + encryptor.finalize()
    end = time.time()
    return to_base64(ct), round(end - start, 6)

def aes_ctr(msg, chave, nonce):
    start = time.time()
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg) + encryptor.finalize()
    end = time.time()
    return to_base64(ct), round(end - start, 6)

# ============================
# EXECUÇÃO DOS TESTES POR MODO
# ============================

resultados = []

modos = [
    ("ECB", aes_ecb, mensagem_bytes, chave, None, "Não", "Vulnerável a padrões repetitivos."),
    ("CBC", aes_cbc, mensagem_bytes, chave, iv, "Sim", "Encadeamento protege contra padrões."),
    ("CFB", aes_cfb, mensagem_bytes, chave, iv, "Sim", "Adequado para streaming, sem padding."),
    ("OFB", aes_ofb, mensagem_bytes, chave, iv, "Sim", "Boa para ambientes com erros de transmissão."),
    ("CTR", aes_ctr, mensagem_bytes, chave, nonce, "Sim (nonce)", "Paralelizável e seguro."),
]

for nome, funcao, msg, key, iv_ou_nonce, usa_iv, comentario in modos:
    base64_saida, tempo = funcao(msg, key, iv_ou_nonce) if iv_ou_nonce else funcao(msg, key)
    resultados.append({
        "Modo": nome,
        "Saída Base64": base64_saida,
        "Tempo (s)": tempo,
        "Usa IV?": usa_iv,
        "Comentário": comentario
    })

# ======================
# EXIBIÇÃO DOS RESULTADOS
# ======================

for resultado in resultados:
    print(f"\nModo: {resultado['Modo']}")
    print(f"Saída em Base64: {resultado['Saída Base64']}")
    print(f"Tempo de Execução: {resultado['Tempo (s)']} segundos")
    print(f"Usa IV? {resultado['Usa IV?']}")
    print(f"Comentário: {resultado['Comentário']}")
