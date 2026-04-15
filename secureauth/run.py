"""
Serve the SecureAuth admin frontend from the Flask API server.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, send_from_directory
from api.server import app, _seed

STATIC_DIR = Path(__file__).parent / "static"

@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(str(STATIC_DIR), path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"\n  SecureAuth running → http://localhost:{port}")
    print(f"  Login: admin / Admin@SecureAuth1!\n")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
