from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib

print("=== Secure File Exchange ===")

# Step 1: Bob makes RSA keys
print("1. Bob making RSA keys...")
key = RSA.generate(2048)

with open("private.pem", "wb") as f:
    f.write(key.export_key())

with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("   Made: private.pem, public.pem")

# Step 2: Alice writes message
print("2. Alice writing message...")
message = "Hello Bob! This is our secret message."
with open("alice_message.txt", "w") as f:
    f.write(message)

# Get original hash
original_hash = hashlib.sha256(message.encode()).hexdigest()
print("   Made: alice_message.txt")

# Step 3: Alice makes AES key and IV
print("3. Alice making AES key...")
aes_key = get_random_bytes(32)
iv = get_random_bytes(16)

# Step 4: Encrypt file with AES
print("4. Encrypting file...")
cipher = AES.new(aes_key, AES.MODE_CBC, iv)

# Read file and add padding
with open("alice_message.txt", "rb") as f:
    data = f.read()

# Add padding
padding = 16 - (len(data) % 16)
data += bytes([padding]) * padding

# Encrypt
encrypted_data = cipher.encrypt(data)

with open("encrypted_file.bin", "wb") as f:
    f.write(encrypted_data)

print("   Made: encrypted_file.bin")

# Step 5: Encrypt AES key with Bob's public key
print("5. Encrypting AES key...")
public_key = RSA.import_key(open("public.pem").read())
rsa_cipher = PKCS1_OAEP.new(public_key)

# Combine key and IV
key_iv = aes_key + iv
encrypted_key = rsa_cipher.encrypt(key_iv)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_key)

print("   Made: aes_key_encrypted.bin")

# Step 6: Bob decrypts AES key
print("6. Bob decrypting AES key...")
private_key = RSA.import_key(open("private.pem").read())
rsa_cipher = PKCS1_OAEP.new(private_key)
decrypted_key_iv = rsa_cipher.decrypt(encrypted_key)

# Split key and IV
dec_aes_key = decrypted_key_iv[:32]
dec_iv = decrypted_key_iv[32:48]

# Step 7: Bob decrypts file
print("7. Bob decrypting file...")
cipher = AES.new(dec_aes_key, AES.MODE_CBC, dec_iv)

with open("encrypted_file.bin", "rb") as f:
    encrypted_data = f.read()

decrypted_data = cipher.decrypt(encrypted_data)

# Remove padding
padding_length = decrypted_data[-1]
decrypted_data = decrypted_data[:-padding_length]

with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_data)

print("   Made: decrypted_message.txt")

# Step 8: Check hash
print("8. Checking file integrity...")
new_hash = hashlib.sha256(decrypted_data).hexdigest()

print(f"   Original hash: {original_hash}")
print(f"   New hash:      {new_hash}")

if original_hash == new_hash:
    print("   ✅ Hashes match - file is good!")
else:
    print("   ❌ Hashes don't match!")

print("\n=== All done! ===")
print(f"Original: {message}")
print(f"Decrypted: {decrypted_data.decode()}")