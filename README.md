# 👑 NimScan 👑
Really fast port scanner (With filtered option - Windows support only)

![Administrator_ Command Prompt 2021-03-09 18-01-21](https://user-images.githubusercontent.com/69467775/110504297-b1a2fb00-8105-11eb-866e-0c438cc1d1a0.gif)

## Benchmarks

| ⚙️ Category|  👁️ Nmap |  🤖 RustScan      |  ♨️ masscan  |  👑 NimScan          |
|    :---:     |     :---:    |     :---:            |      :---:      |      :---:                  |
| Filtered     | ~107 Seconds  | ❌                  |   ❌           | ~60 Seconds (Windows Only)  |
| non-filtered | ~25 Seconds  | ~3 Seconds (Linux)   | ~8 Seconds (Linux)| ~7 Seconds (2 threads)    |
| Dependencies |  Npcap driver |   Nmap              | libpcap driver  | No dependencies             | 
| Can be used as module/library  |    ❌    |   ❌  |      ❌         | ✔️                         |

All bechmarks were performed inside LAN and on 65K ports. 

## Usage
```shell
Usage:
    NimScan <host | IPs> -p:<portX>-<portY> [--timeout=<time>] [--files=<limit of file descriptors>] [-a]
    NimScan <host | IPs> -p:<port>
    NimScan <host | IPs> -p:<port1>,<port2>,<portN>
    NimScan (-h | --help)
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -a, --all             Use rawsockets to find filtered/closed/open ports (Takes longer and limited to 10,000 ports).
    -t, --threads         Number of threads per scan.
    -f, --files=<limit>   File descriptors per thread limit.
    -i, --ignore          Ignore ping latency check.
    --timeout=<time>      Timeout to add to the latency [default: 1500].
```
## Examples
Scan range between 1 to 5000 ports

```shell
NimScan 10.0.0.0/24 -p:1-5000 
```

Scan specific ports
```shell
NimScan 10.0.0.1-10.0.0.10 -p:80,443,445
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
