/*
    Test.c
    gcc test.c -L. -l:NimScanToC.a -w -o NimScan.exe

    Functions:
    scan(char * host, int * ports, int size)
    scanner(char * host, int * ports, int size, char * parameters)
*/
#include <stdio.h>

int main(void)
{
    NimMain(); // A MUST! 

    int ports[] = {1, 445, 8080, 3389, 135, 139};
    int size = sizeof ports / sizeof ports[0];
    const char IP[] = "127.0.0.1"; 
    printf("Scanning %s\n", IP);
    scan(IP, ports, size); // Scan given ports with default configuration (timeout = 1500ms, files = 5000)
    printf("Scanning %s\n", IP);
    scanner(IP, NULL, 0, "--timeout:1000 -f:10000"); // Scanning all 65K ports with timeout of 1,000ms and 10,000 file descriptors
    return 0;
}