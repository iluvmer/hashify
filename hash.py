import hashlib
import os
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
# ensure the uploads directory exists else create it
if not os.path.exists('uploads'):
    os.makedirs('uploads')

class Hash:
    @staticmethod
    def verify_input(input : str) -> bool:
        allowed_file_extentions = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.csv']
        _, file_extension = os.path.splitext(input) #split the file name and the extension
        return file_extension.lower() in allowed_file_extentions #check if the extension (lowercase tho) is in the allowed extensions
    
    @staticmethod
    def validate_mime_type(input : str) -> bool:
        allowed_mime_types = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/gif', 'text/csv']
        return input in allowed_mime_types
    
    @staticmethod
    def validate_file_size(input : int) -> bool:
        # Check the size of the file using file.stream, which is a file-like object.
        input.seek(0, os.SEEK_END)  # Go to the end of the file to get the size
        file_size = input.tell()  # Get the file size
        input.seek(0, os.SEEK_SET)  # Reset the pointer to the beginning of the file
        return file_size <= 1000000  # 1MB
    
    @staticmethod
    def hash_file(input : str , algorithm: str) -> str:
        hash_object = getattr(hashlib, algorithm)()
        with open(input, 'rb') as file:
            chunk = file.read(4096) #read the file's first chunk of 4096 bytes (4KB)

            while chunk: # continue reading the file in chunks until its end
                hash_object.update(chunk) #update the hash object with the chunk data
                chunk = file.read(4096) #read the next chunk
        return hash_object.hexdigest() #return the hash in hexadecimal format
    
    @staticmethod
    def hash_text(input : str , algorithm: str) -> str:
        hash_object = getattr(hashlib, algorithm)()
        hash_object.update(input.encode())
        return hash_object.hexdigest()
    
    @staticmethod
    def custom_hash_text(input: str, key: str) -> str:
        shift_value = sum(ord(c) for c in key) % 256  # Calculate shift value from the key
        shifted_input = ''.join(chr((ord(c) + shift_value) % 256) for c in input)  # Shift each character
        return hashlib.sha256(shifted_input.encode()).hexdigest()  # Hash the shifted input

    @staticmethod
    def custom_hash_file(input: str, key: str) -> str:
        shift_value = sum(ord(c) for c in key) % 256  # Calculate shift value from the key
        shifted_data = b''

        with open(input, 'rb') as file:
            while chunk := file.read(4096):  # Read the file in chunks
                shifted_chunk = bytes([(byte + shift_value) % 256 for byte in chunk])  # Shift each byte
                shifted_data += shifted_chunk

        return hashlib.sha256(shifted_data).hexdigest()  # Hash the shifted data 
    
@app.route('/')
def index():
    return render_template('hashify.html')

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/hashify')
def hashify():
    return render_template('main.html')

@app.route('/hash-text', methods=["POST"])
def hash_text():
    hash_text = request.form.get('text', '')
    algorithm = request.form.get('algorithm', '')
    key = request.form.get('key', '')  # Get the custom key if provided
    hash_result = None

    if not hash_text or (algorithm not in ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'blake2b'] and not key):
        return jsonify({'error': 'Invalid input'}), 400

    if key:
        hash_result = Hash.custom_hash_text(hash_text, key)  # Use the custom hash method with the key
    else:
        hash_result = Hash.hash_text(hash_text, algorithm)  # Use the standard method

    return jsonify({'hash': hash_result})
    

@app.route('/hash-file', methods=["POST"])
def hash_file():
    file = request.files.get('file')
    algorithm = request.form.get('algorithm', '')
    key = request.form.get('key', '')  # Get the custom key if provided
    hash_result = None
    original_content = ""

    if not file or (algorithm not in ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'blake2b'] and not key):
        return jsonify({'error': 'Invalid input'}), 400

    if not Hash.verify_input(file.filename) or not Hash.validate_mime_type(file.mimetype) or not Hash.validate_file_size(file):
        return jsonify({'error': 'Invalid file'}), 400

    # Save the file
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)

    # Check if the file is a text-based file (e.g., .txt, .csv)
    if file.filename.lower().endswith(('.txt', '.csv')):
        try:
            # Read the file content as text (only for text-based files)
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
        except Exception as e:
            return jsonify({'error': f'Error reading file: {str(e)}'}), 500
    else:
        # For binary files, we don't read the content as text
        original_content = "File content cannot be displayed \nas it is binary."

    if key:
        hash_result = Hash.custom_hash_file(file_path, key)  # Use the custom hash method with the key
    else:
        hash_result = Hash.hash_file(file_path, algorithm)  # Use the standard hashing method

    return jsonify({'hash': hash_result, 'fileContent': original_content})

if __name__ == '__main__':
    app.run(debug=True)
    