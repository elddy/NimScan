# 👑 NimScan 👑
Really fast port scanner (With filtered option - Windows support only)

## Benchmarks
|  🚩 Flag 🚩 |  🐧 Linux 🐧  |  🗔 Windows 🗔 |
|    :---:     |     :---:      |     :---:     |
| -f:10,000    | ~9 Seconds      | ~14 Seconds    |
| -f:5,000     | ~16 Seconds     | ~20 Seconds    |

The results are for 65K ports per scan.

## Usage
```shell
Usage:
    NimScan -p:<portX>-<portY> <host> [--timeout=<time>] [--files=<limit of file descriptors>] [-a]
    NimScan -p:<port> <host>
    NimScan -p:<port1>,<port2>,<portN> <host>
    NimScan (-h | --help)
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -a, --all             Use rawsockets to find filtered/closed/open ports (Takes longer and limited to 10,000 ports).       
    -t, --threads         Number of threads per scan.
    -f, --files=<limit>   File descriptors per thread limit.
    --timeout=<time>      Timeout to add to the latency [default: 1500].
```
## Examples
Scan range between 1 to 5000 ports

```shell
NimScan -p:1-5000 10.0.0.69
```

Scan specific ports
```shell
NimScan -p:80,443,445 10.0.0.69
```

Show closed/filtered/open using rawsockets
```shell
NimScan.exe 10.0.0.69 -a
```
## C/C++ Library 🧑🏻‍💻

### Guide

#### Exported functions
```C
scan(char * host, int * ports, int size);
scanner(char * host, int * ports, int size, char * parameters);
```

#### Options
* host        - IP/HOST to scan
* ports       - Ports to scan
* size        - Size of ports array
* parameters  - Parameters to give for the scanner as mentiond above under Usage


#### Create
```C
#include <stdio.h>

int main(void)
{
    NimMain(); // A MUST! 

    int ports[] = {1, 445, 8080, 3389, 135, 139};
    int size = sizeof ports / sizeof ports[0];
    
    scan(<IP/HOST>, ports, size); // Scan given ports with default configuration (timeout = 1500ms, files = 5000)

    scanner(<IP/HOST>, NULL, 0, "<arguments>"); // Scanning all 65K ports with given arguments
    return 0;
}
```

#### Compile

*Make sure NimScanToC.a is in your program's folder.*
```shell
gcc <file>.c -L. -l:NimScanToC.a -w -o NimScan.exe
```
