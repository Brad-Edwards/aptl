#include <windows.h>
#include <stdio.h>

#define IOCTL_CE_INITIALIZE 0x00222034

int main() {
    printf("=== DBK64 Debug Test ===\n");
    
    // Test 1: Simple device open
    printf("\n[Test 1] Opening device...\n");
    HANDLE hDevice = CreateFileW(L"\\\\.\\CEDRIVER73",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,  // No FILE_FLAG_OVERLAPPED for simplicity
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %d\n", GetLastError());
        return 1;
    }
    printf("Device opened successfully: Handle %p\n", hDevice);

    // Test 2: Simple IOCTL with minimal data
    printf("\n[Test 2] Testing simple IOCTL...\n");
    DWORD bytesReturned = 0;
    DWORD testData = 0x12345678;
    
    BOOL result = DeviceIoControl(hDevice,
        IOCTL_CE_INITIALIZE,
        &testData,           // Simple 4-byte input
        4,                   // 4 bytes
        &testData,           // Output to same buffer
        4,                   // 4 bytes output
        &bytesReturned,
        NULL);

    printf("IOCTL result: %s\n", result ? "SUCCESS" : "FAILED");
    if (!result) {
        DWORD error = GetLastError();
        printf("Error: %d (0x%08X)\n", error, error);
    } else {
        printf("Bytes returned: %d\n", bytesReturned);
        printf("Output data: 0x%08X\n", testData);
    }

    // Test 3: Try a different IOCTL to see if it's IOCTL-specific
    printf("\n[Test 3] Testing different IOCTL...\n");
    DWORD otherIoctl = 0x00222000;  // Different code
    
    result = DeviceIoControl(hDevice,
        otherIoctl,
        &testData,
        4,
        &testData,
        4,
        &bytesReturned,
        NULL);

    printf("Different IOCTL result: %s\n", result ? "SUCCESS" : "FAILED");
    if (!result) {
        DWORD error = GetLastError();
        printf("Error: %d (0x%08X)\n", error, error);
    }

    // Test 4: Check if it's a privilege issue by testing without SeDebugPrivilege
    printf("\n[Test 4] This process privilege test (no explicit SeDebugPrivilege enable)...\n");
    printf("If this works but our previous tests failed, it confirms privilege issues\n");
    
    CloseHandle(hDevice);
    return 0;
}
