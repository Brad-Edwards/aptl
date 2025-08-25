#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file_to_backup>\n", argv[0]);
        return 1;
    }
    
    // Escalate to root privileges (this is what makes SUID dangerous)
    setuid(0);
    setgid(0);
    
    char command[256];
    snprintf(command, sizeof(command), "/bin/cp %s /tmp/backup_%d", argv[1], getuid());
    
    // Vulnerable: doesn't properly sanitize input and runs as root
    system(command);
    
    printf("Backup created\n");
    return 0;
}