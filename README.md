# Nim-Port-Scanner
Multi-threaded asynchronous port scanner written in Nim

⚠**Beware of _CPU Usage_ when using substantial amount of ports**⚠

## Usage
```Bash
    ./scanner -p:<portX>-<portY> <host> [--timeout=<time>] [--showAll]
    ./scanner -p:<port> <host> [--timeout=<time>] [--showAll]
    ./scanner -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [--showAll]
```
