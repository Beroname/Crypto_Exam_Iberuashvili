#!/bin/bash
echo "=== Simple Email Encryption ==="

# Step 1: Generate keys
echo "1. Making keys..."
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.asc

# Step 2: Create message
echo "2. Creating message..."
cat > original_message.txt << EOF
Hello Bob,

This is our secret company message.
Meeting is at 3 PM tomorrow.

Best,
Alice
EOF

# Step 3: Sign message
echo "3. Signing message..."
openssl dgst -sha256 -sign private.key -out signature.bin original_message.txt

# Step 4: Encrypt message
echo "4. Encrypting message..."
openssl pkeyutl -encrypt -in original_message.txt -out encrypted_message.bin -pubin -inkey public.asc

# Combine everything for sending
cp encrypted_message.bin signed_message.asc

echo "5. Files created:"
echo "   - original_message.txt"
echo "   - signed_message.asc" 
echo "   - public.asc"
echo "   - private.key"
echo "   - signature.bin"

echo ""
echo "=== Bob's Side: Decrypting ==="

# Step 5: Decrypt message
echo "6. Decrypting message..."
openssl pkeyutl -decrypt -in signed_message.asc -out decrypted_message.txt -inkey private.key

# Step 6: Verify signature
echo "7. Verifying signature..."
if openssl dgst -sha256 -verify public.asc -signature signature.bin decrypted_message.txt; then
    echo "✅ Signature is VALID - Message is from Alice and wasn't changed"
else
    echo "❌ Signature is INVALID - Message was tampered with or not from Alice"
fi

echo ""
echo "Original message:"
cat original_message.txt
echo ""
echo "Decrypted message:"
cat decrypted_message.txt