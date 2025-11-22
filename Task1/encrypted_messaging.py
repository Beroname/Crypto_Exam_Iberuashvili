import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA key pair for User A
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)
    
    print("RSA keys generated: private_key.pem, public_key.pem")
    return public_key

# User B: Encrypt message
def encrypt_message(message, public_key_file):
    # Generate random AES key
    aes_key = get_random_bytes(32)  # 256-bit key
    
    # Encrypt message with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    
    # Encrypt AES key with RSA
    recipient_key = RSA.import_key(open(public_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Save encrypted files
    with open('encrypted_message.bin', 'wb') as f:
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)
    
    with open('aes_key_encrypted.bin', 'wb') as f:
        f.write(encrypted_aes_key)
    
    print("Message encrypted: encrypted_message.bin, aes_key_encrypted.bin")

# User A: Decrypt message
def decrypt_message(private_key_file):
    # Load encrypted files
    with open('encrypted_message.bin', 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    with open('aes_key_encrypted.bin', 'rb') as f:
        encrypted_aes_key = f.read()
    
    # Decrypt AES key with RSA private key
    private_key = RSA.import_key(open(private_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    # Decrypt message with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    # Save decrypted message
    with open('decrypted_message.txt', 'w') as f:
        f.write(message.decode())
    
    print("Message decrypted: decrypted_message.txt")
    return message.decode()

# Main program
def main():
    print("=== Encrypted Messaging App ===\n")
    
    # Step 1: User A generates RSA keys
    print("1. User A generating RSA key pair...")
    generate_rsa_keys()
    
    # Step 2: Create and save original message
    message = "This is a secret message for User A!"
    with open('message.txt', 'w') as f:
        f.write(message)
    print("2. Original message saved: message.txt")
    
    # Step 3: User B encrypts message
    print("3. User B encrypting message...")
    encrypt_message(message, 'public_key.pem')
    
    # Step 4: User A decrypts message
    print("4. User A decrypting message...")
    decrypted_msg = decrypt_message('private_key.pem')
    
    print(f"\nOriginal message: {message}")
    print(f"Decrypted message: {decrypted_msg}")
    print(f"Messages match: {message == decrypted_msg}")

if __name__ == "__main__":
    main()
