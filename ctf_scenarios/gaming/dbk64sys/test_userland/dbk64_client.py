#!/usr/bin/env python3
"""
DBK64 Userland Test Client
Demonstrates communication with DBK64.sys driver
"""

import ctypes
import struct
import sys
from ctypes import wintypes

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

# Device Type
FILE_DEVICE_UNKNOWN = 0x00000022

# Method
METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

# Access
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# Cheat Engine IOCTL Codes (from IOPLDispatcher.h)
IOCTL_CODES = {
    'IOCTL_CE_READMEMORY':      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_WRITEMEMORY':     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_OPENPROCESS':     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_QUERY_VIRTUAL':   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_TEST':            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0804, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_GETPEPROCESS':    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0805, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_READPHYSICAL':    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0806, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_WRITEPHYSICAL':   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0807, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_INITIALIZE':      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x080d, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_GETVERSION':      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0816, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_GETCR4':          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0817, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_ALLOCATEMEM':     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x081f, METHOD_BUFFERED, FILE_ANY_ACCESS),
    'IOCTL_CE_CREATEAPC':       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0820, METHOD_BUFFERED, FILE_ANY_ACCESS),
}

class DBK64Client:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.handle = None
        
    def open_device(self, device_name=r'\\.\DBK64'):
        """Open handle to DBK64 device"""
        print(f"[*] Opening device {device_name}...")
        
        self.handle = self.kernel32.CreateFileW(
            device_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
        
        if self.handle == INVALID_HANDLE_VALUE:
            error = self.kernel32.GetLastError()
            print(f"[-] Failed to open device! Error: {error}")
            return False
            
        print(f"[+] Device opened! Handle: {self.handle}")
        return True
    
    def send_ioctl(self, ioctl_code, input_buffer=None, output_size=256):
        """Send IOCTL to driver"""
        if not self.handle:
            print("[-] Device not opened!")
            return None
            
        # Prepare input
        if input_buffer is None:
            in_buffer = None
            in_size = 0
        else:
            in_buffer = ctypes.create_string_buffer(input_buffer)
            in_size = len(input_buffer)
        
        # Prepare output
        out_buffer = ctypes.create_string_buffer(output_size)
        bytes_returned = wintypes.DWORD()
        
        # Send IOCTL
        result = self.kernel32.DeviceIoControl(
            self.handle,
            ioctl_code,
            in_buffer,
            in_size,
            out_buffer,
            output_size,
            ctypes.byref(bytes_returned),
            None
        )
        
        if result:
            return out_buffer.raw[:bytes_returned.value]
        else:
            return None
    
    def test_driver(self):
        """Run basic driver tests"""
        print("\n=== Testing DBK64 Driver ===\n")
        
        # Test 1: Get Version
        print("[*] Test 1: Get Driver Version")
        result = self.send_ioctl(IOCTL_CODES['IOCTL_CE_GETVERSION'], output_size=4)
        if result:
            version = struct.unpack('<I', result)[0] if len(result) >= 4 else 0
            print(f"[+] Driver version: 0x{version:08X}")
        else:
            error = self.kernel32.GetLastError()
            print(f"[-] Failed! Error: {error}")
        
        # Test 2: Simple Test
        print("\n[*] Test 2: Send TEST IOCTL")
        test_data = b'\x00' * 8
        result = self.send_ioctl(IOCTL_CODES['IOCTL_CE_TEST'], test_data)
        if result:
            print(f"[+] TEST succeeded! Returned {len(result)} bytes")
        else:
            error = self.kernel32.GetLastError()
            print(f"[-] Failed! Error: {error}")
        
        # Test 3: Initialize
        print("\n[*] Test 3: Initialize Driver")
        init_data = struct.pack('<I', 0)
        result = self.send_ioctl(IOCTL_CODES['IOCTL_CE_INITIALIZE'], init_data)
        if result is not None:
            print("[+] Driver initialized!")
        else:
            error = self.kernel32.GetLastError()
            print(f"[-] Failed! Error: {error}")
    
    def map_all_ioctls(self):
        """Try all IOCTL codes to see which respond"""
        print("\n=== Mapping All IOCTLs ===\n")
        
        working_ioctls = []
        
        for name, code in IOCTL_CODES.items():
            # Try with empty input
            result = self.send_ioctl(code, b'\x00' * 8)
            error = self.kernel32.GetLastError() if result is None else 0
            
            status = "SUCCESS" if result is not None else f"ERROR {error}"
            print(f"{name:30} (0x{code:08X}): {status}")
            
            if result is not None:
                working_ioctls.append((name, code))
        
        print(f"\n[+] Found {len(working_ioctls)} working IOCTLs:")
        for name, code in working_ioctls:
            print(f"    {name}: 0x{code:08X}")
        
        return working_ioctls
    
    def close(self):
        """Close device handle"""
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            print("[*] Device handle closed")

def main():
    client = DBK64Client()
    
    if not client.open_device():
        print("Failed to open DBK64 device. Make sure:")
        print("  1. DBK64.sys is loaded (sc start DBK64)")
        print("  2. Registry values A,B,C,D are set")
        print("  3. Running as Administrator")
        return 1
    
    try:
        # Run basic tests
        client.test_driver()
        
        # Map all IOCTLs
        client.map_all_ioctls()
        
    finally:
        client.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())