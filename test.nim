#[
    Test
]#
import asyncdispatch, asyncnet, times, sequtils, threadpool, os

var 
    latency = 1000
    open_ports: array[1..65535, int]

proc connect(host: string, p: int, timeout = latency) {.async.} =
    var client = newAsyncSocket()
    try:
        if await withTimeout(client.connect(host, p.Port), timeout):
            open_ports[p] = p
            echo p, " Open"
    except:
        discard
    finally:
        client.close()
    
proc getChunk(ports: seq[int], chunk: int): seq[int] =
    result = ports[..chunk]

proc scanPorts(host: string, ports: seq[int], chunkOfPorts: int) {.async.} =
    var 
        sacnnedPorts = 1
    for p in ports:
        asyncCheck connect(host, p)
        inc sacnnedPorts
        if sacnnedPorts == chunkOfPorts:
            drain(-1) # Every number chunkOfPorts, wait for events with infinite timeout  
            sacnnedPorts = 1
        await sleepAsync(1)

proc scanEveryChunk(host: string, ports: seq[int], chunkSizeForAsync: int) {.thread.} =
    waitFor scanPorts(host, ports, chunkSizeForAsync)

proc main(host: string, ports: seq[int]) =
    let 
        chunkSizeForThread = 10000 # Every 10,000 ports, create new thread
        chunkSizeForAsync = 1000 # Every 1,000 ports, wait for all async scan in every thread 
    var 
        checkingPorts = ports

    while checkingPorts.len > chunkSizeForThread:
        let chunkSeq = getChunk(checkingPorts, chunkSizeForThread)
        spawn scanEveryChunk(host, chunkSeq, chunkSizeForAsync)
        checkingPorts.delete(0, chunkSizeForThread - 1)
        
    spawn scanEveryChunk(host, checkingPorts, checkingPorts.len) # Passing the last piece of ports sequence and the length of the sequence
    sync()

when isMainModule:
    let 
        host = "10.0.0.39"
        ports = toSeq(1..65535)

    latency = 1000 # Timeout for each connection
    main(host, ports)
    var res = toSeq(open_ports)
    res = filter(res, proc (x: int): bool = x > 0)
    echo "Number of open ports: ", res.len()
    echo cpuTime()
