import hashlib
import json

print("=== Simple File Hash Checker ===")

# Step 1: Create a file
print("\n1. Making original file...")
with open("original.txt", "w") as f:
    f.write("This is my secret file.")

# Step 2: Calculate hashes
print("2. Calculating file hashes...")

# Read the file
with open("original.txt", "rb") as f:
    data = f.read()

# Calculate different hashes
md5_hash = hashlib.md5(data).hexdigest()
sha1_hash = hashlib.sha1(data).hexdigest()
sha256_hash = hashlib.sha256(data).hexdigest()

print("   MD5:    " + md5_hash)
print("   SHA-1:  " + sha1_hash)
print("   SHA-256:" + sha256_hash)

# Step 3: Save hashes to JSON
print("3. Saving hashes to JSON...")
hashes = {
    "MD5": md5_hash,
    "SHA-1": sha1_hash,
    "SHA-256": sha256_hash
}

with open("hashes.json", "w") as f:
    json.dump(hashes, f, indent=2)

print("   Saved: hashes.json")

# Step 4: Tamper with the file
print("\n4. Changing the file...")
with open("tampered.txt", "w") as f:
    f.write("This is my CHANGED file.")

print("   Created: tampered.txt")

# Step 5: Check if file was changed
print("\n5. Checking for changes...")

# Calculate new hashes
with open("tampered.txt", "rb") as f:
    new_data = f.read()

new_md5 = hashlib.md5(new_data).hexdigest()
new_sha1 = hashlib.sha1(new_data).hexdigest()
new_sha256 = hashlib.sha256(new_data).hexdigest()

print("   New MD5:    " + new_md5)
print("   New SHA-1:  " + new_sha1)
print("   New SHA-256:" + new_sha256)

# Compare with original
print("\n6. RESULTS:")
if new_md5 == md5_hash:
    print("   MD5:    ✅ Same (file not changed)")
else:
    print("   MD5:    ❌ Different (file was changed!)")

if new_sha1 == sha1_hash:
    print("   SHA-1:  ✅ Same (file not changed)")
else:
    print("   SHA-1:  ❌ Different (file was changed!)")

if new_sha256 == sha256_hash:
    print("   SHA-256:✅ Same (file not changed)")
else:
    print("   SHA-256:❌ Different (file was changed!)")

print("\n=== Done! ===")