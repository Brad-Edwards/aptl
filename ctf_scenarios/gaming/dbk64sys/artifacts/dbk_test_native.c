#include <windows.h>
#include <stdio.h>

#define IOCTL_CE_INITIALIZE 0x00222034

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("LookupPrivilegeValue failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        printf("AdjustTokenPrivileges failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("SeDebugPrivilege not assigned to token\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    printf("SeDebugPrivilege enabled successfully\n");
    return TRUE;
}

int main() {
    printf("=== DBK64 Native Test ===\n");
    
    // Enable SeDebugPrivilege
    if (!EnableDebugPrivilege()) {
        printf("Failed to enable SeDebugPrivilege\n");
        return 1;
    }

    // Open device
    HANDLE hDevice = CreateFileW(L"\\\\.\\CEDRIVER73",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %d\n", GetLastError());
        return 1;
    }

    printf("Device opened successfully: Handle %p\n", hDevice);

    // Create events
    HANDLE hProcEvent = CreateEventW(NULL, TRUE, FALSE, L"DBKProcList60");
    HANDLE hThreadEvent = CreateEventW(NULL, TRUE, FALSE, L"DBKThreadList60");

    if (!hProcEvent || !hThreadEvent) {
        printf("CreateEvent failed: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("Events created: Process=%p, Thread=%p\n", hProcEvent, hThreadEvent);

    // Build initialization structure (88 bytes)
    BYTE initStruct[88] = {0};
    *((DWORD*)&initStruct[0]) = 0x00000001;  // Some flag
    *((HANDLE*)&initStruct[80]) = hProcEvent;
    *((HANDLE*)&initStruct[80]) = hThreadEvent;  // This overwrites, fix offset

    // Test IOCTL
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice,
        IOCTL_CE_INITIALIZE,
        initStruct,
        sizeof(initStruct),
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (result) {
        printf("SUCCESS! IOCTL_CE_INITIALIZE worked!\n");
        printf("Bytes returned: %d\n", bytesReturned);
    } else {
        printf("IOCTL failed: Error %d\n", GetLastError());
    }

    // Cleanup
    CloseHandle(hProcEvent);
    CloseHandle(hThreadEvent);
    CloseHandle(hDevice);

    return result ? 0 : 1;
}
