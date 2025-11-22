# Secure File Exchange - RSA + AES

This project shows how Alice can send secret files to Bob using encryption.

## How It Works

### Step by Step:

1. **Bob makes keys**
   - Bob creates RSA keys: public.pem (lock) and private.pem (key)
   - Bob shares public.pem with Alice

2. **Alice sends secret file**
   - Alice writes a message in alice_message.txt
   - Alice creates a random AES key (secret code)
   - Alice encrypts the file with AES → encrypted_file.bin
   - Alice encrypts the AES key with Bob's public key → aes_key_encrypted.bin
   - Alice sends both files to Bob

3. **Bob reads the file**
   - Bob uses private.pem to decrypt the AES key
   - Bob uses the AES key to decrypt the file
   - Bob checks the file hash to make sure it wasn't changed

## Files Created

- `alice_message.txt` - Original message (readable)
- `encrypted_file.bin` - Encrypted file (unreadable)
- `aes_key_encrypted.bin` - Encrypted AES key (unreadable)
- `decrypted_message.txt` - Decrypted message (readable)
- `public.pem` - Bob's public key (share this)
- `private.pem` - Bob's private key (keep secret)

## How to Run

1. Install required library:
```bash
pip install pycryptodome