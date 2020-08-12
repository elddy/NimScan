# Nim-Port-Scanner
Multi-threaded asynchronous port scanner written in Nim
**Beware of _CPU Usage_ when using substantial amount of ports**

## Change settings before use
```Nim
when isMainModule:
    let 
        host = "192.168.1.12" # Change as you wish
        ports = @[135, 445, 3389, 5985, 22, 139, 80, 443] # Change as you wish
```
