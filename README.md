Image Steganography with AES Encryption
This project hides a secret message inside an image using AES encryption and Least Significant Bit (LSB) steganography.

Features:
Encrypts a message using AES.
Hides the encrypted message in an image using LSB.
Decodes and decrypts the hidden message.
Requirements:
Python 3.x
Libraries:
opencv-python
pycryptodome
Install the dependencies with:

bash
Copy
pip install opencv-python pycryptodome
Usage:
Encode a Message:
Run the script to hide a secret message inside an image.

bash
Copy
python steganography.py <image_path> <secret_message>
<image_path>: Path to the image.
<secret_message>: The message you want to hide.
Decode and Decrypt:
The script will automatically extract and decrypt the message from the image
