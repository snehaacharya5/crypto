from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --------------------------
# RSA KEY GENERATION
# --------------------------
def generate_rsa_keypair(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    with open(f"keys/{username}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    with open(f"keys/{username}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[+] RSA keys generated for {username}")

# --------------------------
# LOAD KEYS
# --------------------------
def load_public_key(username):
    with open(f"keys/{username}_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(username):
    with open(f"keys/{username}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# --------------------------
# AES ENCRYPTION
# --------------------------
def aes_encrypt(message):
    key = os.urandom(32)  
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return key, iv, encrypted

# --------------------------
# AES DECRYPTION
# --------------------------
def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --------------------------
# SIGN MESSAGE (RSA)
# --------------------------
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# --------------------------
# VERIFY SIGNATURE
# --------------------------
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# --------------------------
# ENCRYPT AES KEY USING RSA
# --------------------------
def encrypt_aes_key(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --------------------------
# DECRYPT AES KEY
# --------------------------
def decrypt_aes_key(private_key, encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
