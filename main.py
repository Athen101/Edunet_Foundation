import argparse
import cv2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Function to encode the image with the message
def encode_image(image, binary_message):
    data_index = 0
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            pixel = image[i, j]
            for c in range(3):  # Iterate through each color channel
                if data_index < len(binary_message):
                    pixel[c] = (pixel[c] & 254) | int(binary_message[data_index])  # Embed bit into the LSB
                    data_index += 1
            image[i, j] = pixel
    return image

# Function to encrypt the message before embedding
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Return IV + ciphertext

# Function to decrypt the message after extraction
def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]  # First 16 bytes are the IV
    ct = encrypted_message[16:]  # Rest is the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)  # Remove padding after decryption
    return decrypted.decode()

# Function to extract the hidden data from the image
def decode_image(image):
    binary_message = ''
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            pixel = image[i, j]
            for c in range(3):
                binary_message += str(pixel[c] & 1)  # Extract LSB (Least Significant Bit) from each pixel channel

    # Define the end marker (%%), represented as a binary string
    end_marker = '00000000' * 2  # Represent %% as 8-bit binary (two bytes for '%%')
    
    # Find the end of the message based on the end marker
    end_marker_index = binary_message.find(end_marker)
    if end_marker_index != -1:
        binary_message = binary_message[:end_marker_index]  # Strip out everything after the end marker

    return binary_message

# Main function to encode and decode image with a secret message
def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Encode and decode secret messages in an image using AES encryption")
    parser.add_argument("image", help="Path to the image file")
    parser.add_argument("message", help="Secret message to hide in the image")
    
    # Parse command-line arguments
    args = parser.parse_args()
    image_path = args.image
    message = args.message
    
    # Check if the image exists before processing
    try:
        image = cv2.imread(image_path)
        if image is None:
            raise FileNotFoundError(f"Error: Image '{image_path}' not found. Please provide a valid image file path.")
    except Exception as e:
        print(e)
        return

    print(f"Using image: {image_path}")
    print(f"Hiding message: {message}")

    # Encrypt the message
    key = get_random_bytes(16)  # Random AES key for encryption
    encrypted_message = encrypt_message(message, key)

    # Convert encrypted message to binary string
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    
    # Add the end marker as part of the message
    end_marker = '00000000' * 2  # Represent %% as 8-bit binary (two bytes for '%%')
    binary_message += end_marker  # Append the end marker

    print("Image loaded successfully.")
    print("Message encrypted successfully.")

    # Encode the encrypted binary message into the image
    encoded_image = encode_image(image, binary_message)

    # Save the encoded image
    cv2.imwrite('encoded_image.jpg', encoded_image)

    # Decode the hidden data from the encoded image
    decoded_binary_message = decode_image(encoded_image)

    # Convert the decoded binary string back to bytes and decrypt it
    try:
        decoded_bytes = bytes(int(decoded_binary_message[i:i+8], 2) for i in range(0, len(decoded_binary_message), 8))
        decrypted_message = decrypt_message(decoded_bytes, key)
        print(f"Decrypted message: {decrypted_message}")
    except ValueError as e:
        print(f"Error during decryption: {e}")

if __name__ == "__main__":
    main()
