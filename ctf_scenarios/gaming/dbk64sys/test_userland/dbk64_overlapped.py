#!/usr/bin/env python3
"""
DBK64 Overlapped I/O Test - Properly handles overlapped operations
"""

import ctypes
import struct
from ctypes import wintypes

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = -1
ERROR_IO_PENDING = 997
WAIT_TIMEOUT = 258
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.windll.kernel32

# OVERLAPPED structure
class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ('Internal', ctypes.c_void_p),
        ('InternalHigh', ctypes.c_void_p),
        ('Offset', wintypes.DWORD),
        ('OffsetHigh', wintypes.DWORD),
        ('hEvent', wintypes.HANDLE)
    ]

def CTL_CODE(DeviceType, Function, Method, Access):
    """Create Windows IOCTL code"""
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

# IOCTL codes
IOCTL_CE_INITIALIZE = CTL_CODE(0x22, 0x080d, 0, 0)
IOCTL_CE_GETVERSION = CTL_CODE(0x22, 0x0816, 0, 0)

print("=== DBK64 Overlapped I/O Test ===\n")

# Open device with overlapped flag
print("[*] Opening device with FILE_FLAG_OVERLAPPED...")
handle = kernel32.CreateFileW(
    r'\\.\DBK64',
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    None,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,
    None
)

if handle == INVALID_HANDLE_VALUE:
    print(f"[-] Failed to open device! Error: {kernel32.GetLastError()}")
    exit(1)

print(f"[+] Device opened! Handle: {handle}\n")

# Create event for overlapped operation
io_event = kernel32.CreateEventW(None, True, False, None)  # Manual reset event
if io_event == 0:
    print("[-] Failed to create I/O event!")
    kernel32.CloseHandle(handle)
    exit(1)

# Create process/thread events for initialization
process_event = kernel32.CreateEventW(None, False, False, None)
thread_event = kernel32.CreateEventW(None, False, False, None)

print(f"[+] Created events - IO: {io_event}, Process: {process_event}, Thread: {thread_event}\n")

# Initialize driver with overlapped I/O
print("[*] Initializing driver with overlapped I/O...")

init_struct = struct.pack('<' + 'Q' * 11,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    process_event,
    thread_event
)

in_buffer = ctypes.create_string_buffer(init_struct)
out_buffer = ctypes.create_string_buffer(8)
bytes_returned = wintypes.DWORD()

# Create OVERLAPPED structure
overlapped = OVERLAPPED()
overlapped.hEvent = io_event

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_INITIALIZE,
    in_buffer,
    len(init_struct),
    out_buffer,
    8,
    ctypes.byref(bytes_returned),
    ctypes.byref(overlapped)
)

if not result:
    error = kernel32.GetLastError()
    if error == ERROR_IO_PENDING:
        print("[*] I/O pending, waiting for completion...")
        
        # Wait for the operation to complete
        wait_result = kernel32.WaitForSingleObject(io_event, 5000)  # 5 second timeout
        
        if wait_result == 0:  # WAIT_OBJECT_0
            # Get the result
            if kernel32.GetOverlappedResult(
                handle,
                ctypes.byref(overlapped),
                ctypes.byref(bytes_returned),
                False
            ):
                print("[+] Initialization completed successfully!")
                if bytes_returned.value >= 8:
                    sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
                    print(f"    SDTShadow: 0x{sdt_shadow:016X}")
            else:
                print(f"[-] GetOverlappedResult failed! Error: {kernel32.GetLastError()}")
        elif wait_result == WAIT_TIMEOUT:
            print("[-] Timeout waiting for operation!")
            kernel32.CancelIo(handle)
        else:
            print(f"[-] Wait failed! Result: {wait_result}")
    else:
        print(f"[-] DeviceIoControl failed! Error: {error}")
else:
    print("[+] Initialization completed immediately!")
    if bytes_returned.value >= 8:
        sdt_shadow = struct.unpack('<Q', out_buffer.raw[:8])[0]
        print(f"    SDTShadow: 0x{sdt_shadow:016X}")

print()

# Test GETVERSION with overlapped I/O
print("[*] Testing GETVERSION with overlapped I/O...")
kernel32.ResetEvent(io_event)  # Reset event for next operation

out_buffer = ctypes.create_string_buffer(4)
bytes_returned = wintypes.DWORD()
overlapped = OVERLAPPED()
overlapped.hEvent = io_event

result = kernel32.DeviceIoControl(
    handle,
    IOCTL_CE_GETVERSION,
    None,
    0,
    out_buffer,
    4,
    ctypes.byref(bytes_returned),
    ctypes.byref(overlapped)
)

if not result:
    error = kernel32.GetLastError()
    if error == ERROR_IO_PENDING:
        print("[*] I/O pending, waiting...")
        wait_result = kernel32.WaitForSingleObject(io_event, 5000)
        
        if wait_result == 0:
            if kernel32.GetOverlappedResult(
                handle,
                ctypes.byref(overlapped),
                ctypes.byref(bytes_returned),
                False
            ):
                version = struct.unpack('<I', out_buffer.raw[:4])[0]
                print(f"[+] SUCCESS! Driver version: 0x{version:08X}")
            else:
                print(f"[-] GetOverlappedResult failed! Error: {kernel32.GetLastError()}")
        else:
            print("[-] Timeout or wait failed!")
    else:
        print(f"[-] Failed! Error: {error}")
else:
    version = struct.unpack('<I', out_buffer.raw[:4])[0]
    print(f"[+] SUCCESS! Driver version: 0x{version:08X}")

# Cleanup
print("\n[*] Cleaning up...")
kernel32.CloseHandle(io_event)
kernel32.CloseHandle(process_event)
kernel32.CloseHandle(thread_event)
kernel32.CloseHandle(handle)
print("[+] Done!")