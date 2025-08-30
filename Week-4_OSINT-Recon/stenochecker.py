import hashlib
from PIL import Image
import sys


# -------------------------------
# Step 1: Generate Hash of Target File
# -------------------------------
def generate_hash(file_path, algorithm="sha256"):
    with open(file_path, "rb") as f:
        data = f.read()
        if algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha3_256":
            return hashlib.sha3_256(data).hexdigest()
        else:
            raise ValueError("Unsupported algorithm")


# -------------------------------
# Step 2: Embed Hash into Cover Image (LSB Steganography)
# -------------------------------
def embed_hash(cover_image_path, hash_value, output_image_path):
    img = Image.open(cover_image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    binary_hash = ''.join(format(ord(c), '08b') for c in hash_value)
    pixels = list(img.getdata())

    if len(binary_hash) > len(pixels) * 3:
        raise ValueError("Hash too large for this image!")

    new_pixels = []
    hash_index = 0

    for pixel in pixels:
        r, g, b = pixel
        if hash_index < len(binary_hash):
            r = (r & ~1) | int(binary_hash[hash_index])
            hash_index += 1
        if hash_index < len(binary_hash):
            g = (g & ~1) | int(binary_hash[hash_index])
            hash_index += 1
        if hash_index < len(binary_hash):
            b = (b & ~1) | int(binary_hash[hash_index])
            hash_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_image_path)
    print(f"[+] Hash embedded into {output_image_path}")


# -------------------------------
# Step 3: Extract Hash from Image
# -------------------------------
def extract_hash(stego_image_path, hash_length=64):
    img = Image.open(stego_image_path)
    pixels = list(img.getdata())
    binary_hash = ""

    for pixel in pixels:
        for color in pixel[:3]:
            binary_hash += str(color & 1)

    # Extract only needed bits
    binary_hash = binary_hash[:hash_length * 8]
    extracted = ''.join(chr(int(binary_hash[i:i+8], 2)) for i in range(0, len(binary_hash), 8))
    return extracted


# -------------------------------
# Step 4: Verify Integrity
# -------------------------------
def verify_integrity(target_file, stego_image_path):
    extracted_hash = extract_hash(stego_image_path)
    current_hash = generate_hash(target_file)

    print("[*] Extracted Hash: ", extracted_hash)
    print("[*] Current File Hash: ", current_hash)

    if extracted_hash == current_hash:
        print("[+] File integrity verified. No modification detected.")
    else:
        print("[-] Integrity check failed! File has been modified.")


# -------------------------------
# Demo Run
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage:")
        print(" python stenochecker.py <mode> <target_file> <cover_image/stego_image>")
        print(" Modes: embed / verify")
        sys.exit(1)

    mode = sys.argv[1]
    target_file = sys.argv[2]
    cover_or_stego = sys.argv[3]

    if mode == "embed":
        file_hash = generate_hash(target_file)
        embed_hash(cover_or_stego, file_hash, "stego_output.png")

    elif mode == "verify":
        verify_integrity(target_file, cover_or_stego)
