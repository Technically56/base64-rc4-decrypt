import csv
from Crypto.Cipher import ARC4
import sys
import base64

if len(sys.argv) < 5:
    print("Usage: python3 rc4.py <passphrase> <input_csv> <output_csv> <seperator>")
    print("Decodes Base64 encoded RC4 encrypted strings.")
    sys.exit(0)
if sys.argv[1] == "--help" or sys.argv[1] == "-h":
    print("Usage: python3 rc4.py <passphrase> <input_csv> <output_csv> <seperator>")
    print("Decodes Base64 encoded RC4 encrypted strings.")
    sys.exit(0)

passphrase = sys.argv[1]
ciphertext_file = sys.argv[2]
output_file = sys.argv[3]
seperator = sys.argv[4]


def fix_padding(b64_string):
    if not b64_string:
        return ""
    b64_string = b64_string.strip()
    missing_padding = len(b64_string) % 4
    if missing_padding:
        b64_string += "=" * (4 - missing_padding)
    return b64_string


def decrypt_base64_rc4(passphrase, b64_ciphertext):
    clean_b64 = fix_padding(b64_ciphertext)
    cipher = ARC4.new(passphrase.encode("utf-8"))
    encrypted_bytes = base64.b64decode(clean_b64)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)

    try:
        plaintext = decrypted_bytes.decode("utf-8")
        return plaintext.replace("\x00", "?")
    except UnicodeDecodeError:
        plaintext = f"<Binary Data: {decrypted_bytes.hex()}>"

    return plaintext


try:
    with open(ciphertext_file, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)

        with open(output_file, "w", newline="", encoding="utf-8") as outfile:
            writer = csv.writer(
                outfile,
                delimiter=seperator,
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL,
                escapechar="\\",
            )
            for row in reader:
                if not row:
                    continue

                b64_ciphertext = row[0]
                plaintext = decrypt_base64_rc4(passphrase, b64_ciphertext)

                writer.writerow([b64_ciphertext, plaintext])

    print(f"Decrypted strings written to: {output_file}")

except FileNotFoundError:
    print(f"Error: file '{ciphertext_file}' not found.")
except Exception as e:
    print(f"Error: {e}")
