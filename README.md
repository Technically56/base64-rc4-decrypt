# base64-rc4-decrypt
A simple Python utility to batch decrypt RC4-encrypted data stored in CSV files. It handles Base64 decoding, padding repairs, and safe text output.

Install: pip3 install -r requirements.txt

Usage: python3 rc4.py <passphrase> <input_csv> <output_csv> <seperator>

Note: Decrypted NULL bytes will be converted to "?" to make string parsing easier. This can be changed inside the code by modifying the nullReplaceChar variable.
