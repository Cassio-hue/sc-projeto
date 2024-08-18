# MGF1: https://en.wikipedia.org/wiki/Mask_generation_function
# ASN: https://gist.github.com/ppoffice/e10e0a418d5dafdd5efe9495e962d3d2
# RSAES-OAEP: https://www.bilibili.com/video/BV1iS4y1G7Rk/?spm_id_from=333.337.search-card.all.click

import sympy
import random
import hashlib
import base64

NUM_BITS = 1024
SEED_LENGTH = 256
PADDING_LENGTH = 256
HASH_FUNC = hashlib.sha256

# Gera um número primo com NUM_BITS bits
# return: número primo com NUM_BITS bits
def gen_prime():
    while True:
        min_bits = 2 ** (NUM_BITS - 1)
        max_bits = 2 ** NUM_BITS - 1

        prime_number = sympy.randprime(min_bits, max_bits)

        if sympy.isprime(prime_number):
            return prime_number


# Calcula o MDC entre dois números
# a: número a
# b: número b
# return: MDC entre a e b
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Calcula o inverso modular de a mod m
# a: número a
# m: número m
# return: inverso modular de a mod m
def modinv(a, m):
    m0, y, x = m, 0, 1

    if m == 1:
        return 0

    while a > 1:
        q = a // m
        m, a = a % m, m
        y, x = x - q * y, y
    
    return x + m0 if x < 0 else x


# Gera as chaves pública e privada
# return: tupla com a chave pública e a chave privada
def generate_keys():
    p = gen_prime()
    q = gen_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = modinv(e, phi)

    return (e, n), (d, n)


# Realiza o XOR em duas listas de bytes
# Mesma função usada no aes.py
# a: lista de bytes
# b: lista de bytes
# return: resultado a XOR b
def xor_bytes(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])


# Implementação do MGF1
# seed: valor inicial usado para gerar a máscara
# mask_len: tamanho da máscara em bytes
# return: máscara gerada
def mgf1(seed, mask_len):
    hlen = HASH_FUNC().digest_size

    output = b""

    for i in range(0, -(-mask_len // hlen)):
        c = i.to_bytes(4, 'big')
        output += HASH_FUNC(seed + c).digest()

    return output[:mask_len]


# Implementação do OAEP para cifrar a mensagem
# message: mensagem a ser cifrada
# n: tamanho da chave em bytes
def oaep_encode(message, n):
    mlen = len(message)
    pad = b'\x00' * (n - mlen - PADDING_LENGTH // 8 - 2)
    db = pad + b'\x01' + message

    seed = random.getrandbits(SEED_LENGTH).to_bytes(SEED_LENGTH // 8, 'big')
    db_mask = mgf1(seed, len(db))
    masked_db = xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, SEED_LENGTH // 8)
    masked_seed = xor_bytes(seed, seed_mask)

    return b'\x00' + masked_seed + masked_db


# Função para cifrar a mensagem usando a chave pública
# plaintext: mensagem a ser cifrada
# public_key: chave pública
# return: mensagem cifrada
def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    k = (n.bit_length() + 7) // 8 
    encoded_message = oaep_encode(plaintext, k)
    plaintext_int = int.from_bytes(encoded_message, 'big')
    ciphertext = pow(plaintext_int, e, n)

    return ciphertext


# Implementação do OAEP para decifrar a mensagem
# encoded_message: mensagem cifrada
# k: tamanho da chave em bytes
# return: mensagem decifrada
def oaep_decode(encoded_message, k):
    encoded_message = encoded_message[1:]

    masked_seed = encoded_message[:SEED_LENGTH // 8]
    masked_db = encoded_message[SEED_LENGTH // 8:]

    seed_mask = mgf1(masked_db, SEED_LENGTH // 8)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, len(masked_db))
    db = xor_bytes(masked_db, db_mask)

    lhash_len = len(HASH_FUNC().digest())
    ps_end = db.index(b'\x01', lhash_len)
    message = db[ps_end + 1:]

    return message


# Função para decifrar a mensagem usando a chave privada
# ciphertext: mensagem cifrada
# private_key: chave privada
# return: mensagem decifrada
def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    k = (n.bit_length() + 7) // 8
    plaintext_int = pow(ciphertext, d, n)
    plaintext = plaintext_int.to_bytes(k, 'big')

    return oaep_decode(plaintext, k)


# Função para calcular o hash de um arquivo
# file_path: caminho do arquivo
# return: hash do arquivo
def calculate_hash(file_path):
    sha3 = hashlib.sha3_256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha3.update(chunk)

    return sha3.digest()


# Função que assina um arquivo
# file_path: caminho do arquivo
# private_key: chave privada
# return: assinatura do arquivo formatada
def sign_file(file_path, private_key):
    hash = calculate_hash(file_path)
    signature = rsa_encrypt(hash, private_key)
    formatted_signature = base64.b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, 'big')).decode()

    return formatted_signature


# Função para verificar a assinatura de um arquivo
# file_path: caminho do arquivo
# base64_signature: assinatura em base64
# public_key: chave pública
# return: True se a assinatura é válida, False caso não
def verify_file(file_path, base64_signature, public_key):
    signature = int.from_bytes(base64.b64decode(base64_signature), 'big')
    decrypted_hash = rsa_decrypt(signature, public_key)
    current_hash = calculate_hash(file_path)

    return decrypted_hash == current_hash


public_key, private_key = generate_keys()
print()
print()
print("Public Key:", public_key)
print()
print("Private Key:", private_key)
print()
print()

message = "Mensagem a ser cifrada usando RSA"

ciphertext = rsa_encrypt(message.encode(), public_key)

decrypted_message = rsa_decrypt(ciphertext, private_key).decode()

print("Mensagem original:", message)
print()
print("Mensagem cifrada:", ciphertext)
print()
print("Mensagem decifrada:", decrypted_message)
print()
print("Mensagem Original == Mensagem Decifrada:", message == decrypted_message)
print()
print()

file_path = "cic0201-2024-1-Trab-1.pdf"
signature = sign_file(file_path, private_key)
print("Assinatura em Base64:")
print(signature)
print()
print()

is_valid = verify_file(file_path, signature, public_key)
if is_valid:
    print("Assinatura válida.")
else:
    print("Assinatura inválida.")