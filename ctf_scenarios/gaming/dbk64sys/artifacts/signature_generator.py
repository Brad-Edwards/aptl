#!/usr/bin/env python3
"""
DBK64 Signature Generator

Creates a valid .sig file for the DBK64 driver authentication.
Based on the signature validation logic in sigcheck.c
"""

import hashlib
import struct
import sys
import os

# Public key from sigcheck.c line 16
PUBLIC_KEY = bytes([
    0x45, 0x43, 0x53, 0x35, 0x42, 0x00, 0x00, 0x00, 0x00, 0x3A, 0xBA, 0x72, 0xCF, 0xA7, 0x79, 0xFA, 
    0x92, 0x96, 0x15, 0x8E, 0x69, 0x35, 0x19, 0x09, 0x99, 0x3C, 0x97, 0xE8, 0x18, 0x0B, 0xC6, 0x2C, 
    0x8B, 0x24, 0x5A, 0xD8, 0x1C, 0x86, 0x83, 0x89, 0xE7, 0xA4, 0xA9, 0x47, 0x11, 0x7E, 0x07, 0x74, 
    0x69, 0x74, 0x33, 0x0B, 0x1A, 0xB8, 0x63, 0x11, 0x51, 0xEA, 0x00, 0xD6, 0x26, 0xE7, 0x7C, 0x6D, 
    0x77, 0xA5, 0x0E, 0x9F, 0x37, 0x87, 0x7B, 0x79, 0x2F, 0xEE, 0x00, 0x65, 0x7A, 0xBF, 0x44, 0x79, 
    0xD1, 0x7E, 0x47, 0xBC, 0xF9, 0x6F, 0x31, 0x81, 0x85, 0x70, 0x78, 0x5D, 0xED, 0xA5, 0xC6, 0x15, 
    0x0F, 0x2C, 0x0A, 0x27, 0x3B, 0x3E, 0x36, 0xEB, 0x53, 0x3E, 0x3E, 0x75, 0xC1, 0xA3, 0x0A, 0xC0, 
    0xC1, 0x53, 0x3A, 0x77, 0xFB, 0x84, 0x88, 0x35, 0xE8, 0x86, 0xF0, 0xA2, 0x52, 0x86, 0x5D, 0x12, 
    0x2D, 0x03, 0x88, 0x00, 0x36, 0x2B, 0x8D, 0x21, 0x13, 0x99, 0x7F, 0x62
])

def create_dummy_signature(exe_path, sig_path):
    """
    Create a dummy signature file.
    
    Note: This creates a syntactically valid signature file, but the actual
    cryptographic signature will be invalid since we don't have Dark Byte's
    private key. The driver will still reject it, but this demonstrates
    the signature file format.
    """
    print(f"[*] Creating dummy signature for: {exe_path}")
    print(f"[*] Output signature file: {sig_path}")
    
    # Read the executable file
    try:
        with open(exe_path, 'rb') as f:
            exe_data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Executable file not found: {exe_path}")
        return False
    except Exception as e:
        print(f"[-] Error reading executable: {e}")
        return False
    
    print(f"[+] Read {len(exe_data)} bytes from executable")
    
    # Calculate SHA-512 hash (as per CheckSignature function)
    sha512_hash = hashlib.sha512(exe_data).digest()
    print(f"[+] SHA-512 hash: {sha512_hash.hex()}")
    
    # Create dummy ECDSA P-521 signature (132 bytes)
    # This is obviously fake since we don't have the private key
    dummy_signature = b'\x00' * 132  # Invalid signature
    
    print(f"[+] Created dummy signature ({len(dummy_signature)} bytes)")
    
    # Write signature file
    try:
        with open(sig_path, 'wb') as f:
            f.write(dummy_signature)
        print(f"[+] Signature file created: {sig_path}")
        return True
    except Exception as e:
        print(f"[-] Error writing signature file: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python signature_generator.py <executable_path>")
        print("Example: python signature_generator.py C:\\Python313\\python.exe")
        return
    
    exe_path = sys.argv[1]
    sig_path = exe_path + ".sig"
    
    print("=== DBK64 Signature Generator ===")
    print(f"Executable: {exe_path}")
    print(f"Signature: {sig_path}")
    print()
    
    success = create_dummy_signature(exe_path, sig_path)
    
    if success:
        print()
        print("[+] Signature file created successfully!")
        print("[!] NOTE: This is a DUMMY signature - it will NOT pass validation")
        print("[!] The driver requires a signature from Dark Byte's private key")
        print("[!] This demonstrates the signature file format only")
    else:
        print()
        print("[-] Failed to create signature file")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
