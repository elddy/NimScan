# NimScan
Multithreaded asynchronous port scanner (With filtered option) written in Nim for Windows

## Benchmarks
![](gif/Scanner.gif)

## Usage
```Bash
nimscan.exe -p:<portX>-<portY> <host> [--timeout=<time>] [--files=<limit of file descriptors>] [-a]
nimscan.exe -p:<port> <host>
nimscan.exe -p:<port1>,<port2>,<portN> <host>
    -h, --help        Show this screen.
    -p, --ports       Ports to scan.
    -a, --all         Use rawsockets to find filtered/closed/open ports (Takes longer and less reliable).       
    --timeout=<time>  Timeout to add to the latency [default: 1500].
    --files=<limit>   File descriptors per thread limit.
    
```
## Examples
Scan range between 1 to 5000 ports

```Bash
nimscan.exe -p:1-5000 10.0.0.69
```

Scan specific ports
```Bash
nimscan.exe -p:80,443,445 10.0.0.69
```

Show closed/filtered/open using rawsockets
```Bash
nimscan.exe 10.0.0.69 -a
```
