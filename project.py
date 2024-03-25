#NM1142
#Nouman Mohammed




import sqlite3
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify
import logging
import os

# Initialize Flask app
app = Flask(__name__)

# Configure SQLite database path
DATABASE_PATH = 'totally_not_my_privateKeys.db'

# Initialize database if it doesn't exist
def initialize_database():
    if not os.path.isfile(DATABASE_PATH):
        db_connection = sqlite3.connect(DATABASE_PATH)
        db_cursor = db_connection.cursor()
        db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        db_connection.commit()
        db_connection.close()

# Ensure database initialization on application start
initialize_database()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to generate a new private key in PEM format
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_pem

# Route to save a new private key
@app.route('/save_key', methods=['POST'])
def save_key():
    try:
        # Generate a new private key and save it to the database
        private_key = generate_private_key()
        exp = request.form.get('exp')

        db_connection = sqlite3.connect(DATABASE_PATH)
        db_cursor = db_connection.cursor()
        db_cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (private_key, exp))
        db_connection.commit()
        db_connection.close()

        return jsonify({'message': 'Key saved successfully'})
    except Exception as e:
        logger.error('Error saving key: %s', str(e))
        return jsonify({'error': 'Key not saved'})

# Route to authenticate user and generate JWT
@app.route('/auth', methods=['POST'])
def authenticate_user():
    try:
        # Read a private key from the database
        expired = request.args.get('expired')

        db_connection = sqlite3.connect(DATABASE_PATH)
        db_cursor = db_connection.cursor()

        if expired:
            db_cursor.execute('SELECT key FROM keys WHERE exp <= strftime("%s", "now")')
        else:
            db_cursor.execute('SELECT key FROM keys WHERE exp > strftime("%s", "now")')

        result = db_cursor.fetchone()

        if result:
            private_key = result[0]
            token = jwt.encode({'data': 'your_data'}, private_key, algorithm='RS256')
            return jsonify({'jwt': token})
        else:
            return jsonify({'message': 'No valid private key found'})
    except Exception as e:
        logger.error('Error authenticating user: %s', str(e))
        return jsonify({'error': 'Authentication failed'})

# Route to get JWKS JSON
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    try:
        # Fetch non-expired private keys from the database and create a JWKS response
        db_connection = sqlite3.connect(DATABASE_PATH)
        db_cursor = db_connection.cursor()
        db_cursor.execute('SELECT kid, key FROM keys WHERE exp > strftime("%s", "now")')
        keys = [{'kid': str(kid), 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'n': key} for kid, key in db_cursor.fetchall()]
        jwks = {'keys': keys}
        return jsonify(jwks)
    except Exception as e:
        logger.error('Error retrieving JWKS: %s', str(e))
        return jsonify({'error': 'JWKS retrieval failed'})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
