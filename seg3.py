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

# Chave AES-128 (16 bytes)
chave = b'1234567890abcdef'

# IV de 16 bytes para CBC, CFB, OFB
iv = b'abcdef1234567890'

# Nonce de 16 bytes para CTR
nonce = b'1234567890abcdef'

# =====================
# FUNÇÕES AUXILIARES
# =====================

def to_base64(data_bytes: bytes) -> str:
    """Converte bytes para string Base64."""
    return b64encode(data_bytes).decode('utf-8')

def aplicar_padding(data: bytes) -> bytes:
    """Aplica PKCS#7 padding de bloco de 128 bits."""
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def medir_tempo(func, *args, **kwargs):
    """Executa func(*args, **kwargs), mede tempo e retorna (resultado, tempo)."""
    t0 = time.perf_counter()
    resultado = func(*args, **kwargs)
    t1 = time.perf_counter()
    return resultado, round(t1 - t0, 6)

# =====================
# FUNÇÕES POR MODO AES
# =====================

def aes_ecb(msg: bytes, key: bytes) -> bytes:
    """AES-ECB: requer padding."""
    msg_padded = aplicar_padding(msg)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(msg_padded) + encryptor.finalize()

def aes_cbc(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC: requer padding e IV único para cada cifragem."""
    msg_padded = aplicar_padding(msg)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(msg_padded) + encryptor.finalize()

def aes_cfb(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CFB: não requer padding, adequado para streaming."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def aes_ofb(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-OFB: não requer padding, tolerante a erros de transmissão."""
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def aes_ctr(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES-CTR: não requer padding, paralelizável, usa nonce."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

# ============================
# EXECUÇÃO DOS TESTES POR MODO
# ============================

modos = [
    ("ECB", aes_ecb,      (mensagem_bytes, chave),     "Não", "Vulnerável a padrões repetitivos."),
    ("CBC", aes_cbc,      (mensagem_bytes, chave, iv), "Sim",  "Encadeamento protege contra padrões."),
    ("CFB", aes_cfb,      (mensagem_bytes, chave, iv), "Sim",  "Adequado para streaming, sem padding."),
    ("OFB", aes_ofb,      (mensagem_bytes, chave, iv), "Sim",  "Resistente a erros de transmissão."),
    ("CTR", aes_ctr,      (mensagem_bytes, chave, nonce), "Sim (nonce)", "Paralelizável e seguro."),
]

print(f"Mensagem teste: “{mensagem}”")
print(f"Chave AES-128: {chave!r}")
print(f"IV (CBC/CFB/OFB): {iv!r}")
print(f"Nonce (CTR): {nonce!r}\n")

resultados = []
for nome, func, args, usa_iv, comentario in modos:
    ct_bytes, tempo = medir_tempo(func, *args)
    ct_b64 = to_base64(ct_bytes)
    resultados.append({
        "Modo": nome,
        "Saída Base64": ct_b64,
        "Tempo (s)": tempo,
        "Usa IV?": usa_iv,
        "Comentário": comentario
    })

# ======================
# EXIBIÇÃO DOS RESULTADOS
# ======================
import tabulate
print(tabulate.tabulate(
    [r.values() for r in resultados],
    headers=resultados[0].keys(),
    tablefmt="github"
))
