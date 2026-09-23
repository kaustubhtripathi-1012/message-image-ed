#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecureVault dev server — run from the project root."""
import sys, os

# Add backend directory to path so we can import app directly
BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend')
sys.path.insert(0, BACKEND_DIR)

# pyrefly: ignore [missing-import]
from app import app   # import app.py from backend/

if __name__ == '__main__':
    print("\n ======================================= ")
    print("   || SecureVault — E2EE Demo Server    ||")
    print("   || http://127.0.0.1:5000             ||")
    print("   ======================================= \n")
    app.run(debug=True, port=5000, host='127.0.0.1')
