# Nim-Port-Scanner
Multi-threaded asynchronous port scanner written in Nim

⚠**Beware of _CPU Usage_ when using substantial amount of ports**⚠

## Usage
```Bash
./scanner -p:<portX>-<portY> <host> [--timeout=<time>] [--showAll]
./scanner -p:<port> <host> [--timeout=<time>] [--showAll]
./scanner -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [--showAll]
```
## Examples
Scan range between 1 to 65535 ports

```Bash
./Scanner -p:1-65535 10.0.0.69
```

Scan specific ports
```Bash
./Scanner -p:80,443,445 10.0.0.69
```

Show also closed ports
```Bash
./Scanner -p:1-65535 10.0.0.69 --showAll
```
