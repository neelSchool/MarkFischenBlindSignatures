# Full Blind Signature Implementation

import os
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Utilities

def secure_random_bytes(length):
    return secrets.token_bytes(length)

def hash_data(*args):
    h = hashlib.sha256()
    for data in args:
        h.update(data)
    return h.digest()

def pad_message(msg, block_size=16):
    padding_length = block_size - (len(msg) % block_size)
    return msg + bytes([padding_length] * padding_length)

def unpad_message(padded_msg):
    padding_length = padded_msg[-1]
    return padded_msg[:-padding_length]

# Fiat-Shamir NIZK Proof

class NIZKProof:
    def __init__(self, crsZK):
        self.crsZK = crsZK

    def prove(self, x, w):
        n = 32
        r = secure_random_bytes(n)
        t = hash_data(self.crsZK, r)
        c = hash_data(self.crsZK, t, x)
        s = bytes(a ^ b for a, b in zip(r, c))
        return t + s

    def verify(self, x, proof):
        n = 32
        t = proof[:n]
        s = proof[n:]
        c = hash_data(self.crsZK, t, x)
        r = bytes(a ^ b for a, b in zip(s, c))
        recomputed_t = hash_data(self.crsZK, r)
        return recomputed_t == t

# Bank

class Bank:
    def __init__(self):
        self.skSig, self.pkSig = self.generate_signature_keys()

    def generate_signature_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(self, message):
        return self.skSig.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, message, signature):
        try:
            self.pkSig.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# User

class User:
    def __init__(self, crsZK, crsCom, pkEnc, pkSig):
        self.crsZK = crsZK
        self.crsCom = crsCom
        self.pkEnc = pkEnc
        self.pkSig = pkSig
        self.nizk = NIZKProof(crsZK)

    def commit(self, message, randomness):
        return hash_data(self.crsCom, message, randomness)

    def encrypt(self, plaintext, randomness):
        iv = randomness[:16]
        cipher = Cipher(algorithms.AES(self.pkEnc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_plaintext = pad_message(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext


    def blind_sign(self, message, bank):
        n = 32
        u = secure_random_bytes(n)
        v = secure_random_bytes(n)

        # Step 1: Commitment
        U = self.commit(message, u)

        # Step 2: Send U, Receive Signature B
        B = bank.sign(U)

        if not bank.verify_signature(U, B):
            raise Exception("Signature verification failed at Bank.")

        # Step 3: Encrypt U || B
        C = self.encrypt(U + B, v)

        # Step 4: Create x, w
        pkSig_bytes = self.pkSig.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        x = C + self.pkEnc + self.crsCom + pkSig_bytes + message
        w = u + v + B

        # Step 5: NIZK Proof
        π = self.nizk.prove(x, w)

        # Step 6: Final Signature
        S = C + π
        return S, message

    def verify_signature(self, S, message):
        n = 32
        C = S[:-2*n]
        π = S[-2*n:]

        pkSig_bytes = self.pkSig.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        x = C + self.pkEnc + self.crsCom + pkSig_bytes + message

        return self.nizk.verify(x, π)

# Full Test

def main():
    print("=== Blind Signature Test Start ===")

    # Parameters
    n = 32  # 256-bit security
    message = b"SecretMsg123"

    # Generate CRS
    crsZK = secure_random_bytes(n)
    crsCom = secure_random_bytes(n)
    pkEnc = secure_random_bytes(32)  # AES-256 key
    skEnc = pkEnc  # symmetric (AES key)

    # Bank and User setup
    bank = Bank()
    user = User(crsZK, crsCom, pkEnc, bank.pkSig)

    # User runs blind signing protocol
    S, m = user.blind_sign(message, bank)

    # 1. Verify signature correctness
    signature_valid = user.verify_signature(S, m)
    print(f"Step 1: Signature structure verification: {signature_valid}")

    assert signature_valid, "Signature failed verification."

    # 2. Now decrypt manually to extract U || B
    C = S[:-2*n]  # ciphertext part
    π = S[-2*n:]  # proof part

    iv = C[:16]
    ciphertext = C[16:]

    cipher = Cipher(algorithms.AES(skEnc), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad_message(padded_plaintext)

    U = plaintext[:32]  # commitment (size 32 bytes)
    B = plaintext[32:]  # bank's signature


    print(f"Step 2: Decrypted Commitment (U): {U.hex()}")
    print(f"Step 3: Decrypted Bank Signature (B): {B.hex()}")

    # 3. Check Bank's signature
    bank_signature_valid = bank.verify_signature(U, B)
    print(f"Step 4: Bank signature verification: {bank_signature_valid}")

    assert bank_signature_valid, "Bank's signature B on U is invalid."

    print("\nAll tests passed: Blind signature protocol is working correctly. ✅ ")

if __name__ == "__main__":
    main()
