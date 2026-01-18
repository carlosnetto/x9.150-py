# Developed in Jan 2026, author carlos.netto@gmail.com.
# Purpose: Validate the X9.150 specification.
# Not for production use; intended only to prove the spec.

import os
from flask import Flask, send_from_directory, abort

app = Flask(__name__)

# Directory where the certificates and JWKS files are located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/<filename>')
def serve_static_file(filename):
    """
    Serves files from the local directory.
    Specifically intended for .pem (certificates) and .jwks files.
    """
    # Security check: Only allow serving specific extensions
    allowed_extensions = {'.pem', '.jwks'}
    _, ext = os.path.splitext(filename)
    
    if ext not in allowed_extensions:
        return abort(403, description="Access to this file type is restricted.")

    if not os.path.isfile(os.path.join(BASE_DIR, filename)):
        return abort(404, description="File not found.")

    return send_from_directory(BASE_DIR, filename)

if __name__ == '__main__':
    # Port 5001 as requested to avoid conflict with qr_server (port 5000)
    app.run(host='127.0.0.1', port=5001)