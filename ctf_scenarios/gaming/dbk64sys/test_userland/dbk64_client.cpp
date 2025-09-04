// DBK64 Test Userland Application
// This demonstrates communication with DBK64.sys driver

#include <windows.h>
#include <stdio.h>

// From Windows DDK
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

// CTL_CODE macro from Windows DDK
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

// Cheat Engine IOCTL codes (from IOPLDispatcher.h)
#define IOCTL_CE_READMEMORY         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_WRITEMEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_OPENPROCESS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_QUERY_VIRTUAL_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_TEST               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_GETPEPROCESS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_GETVERSION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CE_INITIALIZE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x080d, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure for OPENPROCESS command
struct CE_OPENPROCESS_INPUT {
    DWORD ProcessId;
    DWORD DesiredAccess;
};

// Structure for READMEMORY command
struct CE_READMEMORY_INPUT {
    HANDLE ProcessHandle;
    PVOID Address;
    DWORD Size;
};

// Structure for WRITEMEMORY command
struct CE_WRITEMEMORY_INPUT {
    HANDLE ProcessHandle;
    PVOID Address;
    DWORD Size;
    BYTE Data[1]; // Variable length
};

void PrintIOCTLCode(const char* name, DWORD code) {
    printf("%-30s = 0x%08X\n", name, code);
}

int main() {
    printf("=== DBK64 Userland Test Client ===\n\n");
    
    // Print IOCTL codes for reference
    printf("IOCTL Codes:\n");
    PrintIOCTLCode("IOCTL_CE_TEST", IOCTL_CE_TEST);
    PrintIOCTLCode("IOCTL_CE_GETVERSION", IOCTL_CE_GETVERSION);
    PrintIOCTLCode("IOCTL_CE_INITIALIZE", IOCTL_CE_INITIALIZE);
    PrintIOCTLCode("IOCTL_CE_OPENPROCESS", IOCTL_CE_OPENPROCESS);
    PrintIOCTLCode("IOCTL_CE_READMEMORY", IOCTL_CE_READMEMORY);
    PrintIOCTLCode("IOCTL_CE_WRITEMEMORY", IOCTL_CE_WRITEMEMORY);
    printf("\n");

    // Open handle to DBK64 device
    printf("[*] Opening device \\\\.\\ DBK64...\n");
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\DBK64",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device! Error: %d\n", GetLastError());
        printf("    Make sure DBK64.sys is loaded and running\n");
        return 1;
    }

    printf("[+] Device opened successfully! Handle: 0x%p\n\n", hDevice);

    // Test 1: Get Driver Version
    printf("[*] Test 1: Getting driver version...\n");
    DWORD version = 0;
    DWORD bytesReturned = 0;
    
    if (DeviceIoControl(hDevice, IOCTL_CE_GETVERSION, 
                       NULL, 0,
                       &version, sizeof(version),
                       &bytesReturned, NULL)) {
        printf("[+] Driver version: 0x%08X\n", version);
    } else {
        printf("[-] IOCTL_CE_GETVERSION failed! Error: %d\n", GetLastError());
    }

    // Test 2: Simple Test IOCTL
    printf("\n[*] Test 2: Sending TEST IOCTL...\n");
    BYTE testInput[8] = {0};
    BYTE testOutput[8] = {0};
    
    if (DeviceIoControl(hDevice, IOCTL_CE_TEST,
                       testInput, sizeof(testInput),
                       testOutput, sizeof(testOutput),
                       &bytesReturned, NULL)) {
        printf("[+] TEST IOCTL succeeded! Bytes returned: %d\n", bytesReturned);
    } else {
        printf("[-] IOCTL_CE_TEST failed! Error: %d\n", GetLastError());
    }

    // Test 3: Initialize Driver
    printf("\n[*] Test 3: Initializing driver...\n");
    DWORD initValue = 0;
    
    if (DeviceIoControl(hDevice, IOCTL_CE_INITIALIZE,
                       &initValue, sizeof(initValue),
                       NULL, 0,
                       &bytesReturned, NULL)) {
        printf("[+] Driver initialized successfully!\n");
    } else {
        printf("[-] IOCTL_CE_INITIALIZE failed! Error: %d\n", GetLastError());
    }

    // Test 4: Open Current Process
    printf("\n[*] Test 4: Opening current process (PID: %d)...\n", GetCurrentProcessId());
    CE_OPENPROCESS_INPUT openInput;
    openInput.ProcessId = GetCurrentProcessId();
    openInput.DesiredAccess = PROCESS_ALL_ACCESS;
    HANDLE processHandle = NULL;
    
    if (DeviceIoControl(hDevice, IOCTL_CE_OPENPROCESS,
                       &openInput, sizeof(openInput),
                       &processHandle, sizeof(processHandle),
                       &bytesReturned, NULL)) {
        printf("[+] Process opened! Handle: 0x%p\n", processHandle);
    } else {
        printf("[-] IOCTL_CE_OPENPROCESS failed! Error: %d\n", GetLastError());
    }

    // Test 5: Demonstrate Memory Read (if process opened)
    if (processHandle) {
        printf("\n[*] Test 5: Reading memory from current process...\n");
        
        // Prepare read request
        struct {
            CE_READMEMORY_INPUT input;
            BYTE buffer[256];
        } readRequest;
        
        readRequest.input.ProcessHandle = processHandle;
        readRequest.input.Address = (PVOID)&version; // Read our own variable
        readRequest.input.Size = sizeof(DWORD);
        
        BYTE readBuffer[256] = {0};
        
        if (DeviceIoControl(hDevice, IOCTL_CE_READMEMORY,
                           &readRequest, sizeof(CE_READMEMORY_INPUT),
                           readBuffer, sizeof(readBuffer),
                           &bytesReturned, NULL)) {
            printf("[+] Memory read successful! Bytes returned: %d\n", bytesReturned);
            printf("    Value read: 0x%08X\n", *(DWORD*)readBuffer);
        } else {
            printf("[-] IOCTL_CE_READMEMORY failed! Error: %d\n", GetLastError());
        }
    }

    // Cleanup
    printf("\n[*] Closing device handle...\n");
    CloseHandle(hDevice);
    printf("[+] Test complete!\n");

    return 0;
}