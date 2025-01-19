'''start aes'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key, mode=AES.MODE_CBC):
    cipher = AES.new(key, mode)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext, cipher.iv

def aes_decrypt(ciphertext, key, iv, mode=AES.MODE_CBC):
    cipher = AES.new(key, mode, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()
'''start rsa'''
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def rsa_key_generation():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()
'''start hashlib'''
from hashlib import sha256

def sha256_hash(message):
    return sha256(message.encode()).hexdigest()
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

app = Flask(__name__)

@app.route('/api/aes/encrypt', methods=['POST'])
def aes_encrypt():
    data = request.json
    plaintext = data['plaintext']
    key = bytes.fromhex(data['key'])
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return jsonify({
        'ciphertext': ciphertext.hex(),
        'iv': cipher.iv.hex()
    })

@app.route('/api/aes/decrypt', methods=['POST'])
def aes_decrypt():
    data = request.json
    ciphertext = bytes.fromhex(data['ciphertext'])
    key = bytes.fromhex(data['key'])
    iv = bytes.fromhex(data['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return jsonify({
        'plaintext': plaintext.decode()
    })
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

@app.route('/api/rsa/generate', methods=['GET'])
def rsa_generate():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return jsonify({
        'privateKey': private_key,
        'publicKey': public_key
    })

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json
    plaintext = data['plaintext']
    public_key = RSA.import_key(data['publicKey'])
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return jsonify({
        'ciphertext': ciphertext.hex()
    })

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json
    ciphertext = bytes.fromhex(data['ciphertext'])
    private_key = RSA.import_key(data['privateKey'])
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return jsonify({
        'plaintext': plaintext.decode()
    })
from hashlib import sha256

@app.route('/api/sha256/hash', methods=['POST'])
def sha256_hash():
    data = request.json
    message = data['message']
    hash_value = sha256(message.encode()).hexdigest()
    return jsonify({
        'hash': hash_value
    })