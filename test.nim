#[
    Test
]#

import asyncnet, asyncdispatch, sequtils, strutils, times

var open: seq[int]

proc connect(host: string, port: int) {.async.} =
    # echo "Started ", port
    let sock = newAsyncSocket()
    try:
        if await withTimeout(sock.connect(host, port.Port), 1000):
            echo $port, " Open"
            open.add(port)
        # else:
        #     echo $port, " Closed"
    except:
        discard
    sock.close()

proc asyncScan(host: string, ports: seq[int]) {.async.} =
    for p in ports:
        asyncCheck connect(host, p)
    drain(100000)

proc asyncScanChunks(host: string, ports: seq[int]) {.async.} =
    var
        prev = 0
        next = 0
        divide = (ports.len / 5000).toInt()

    for i in 1..divide:
        next = (i * 5000) - 1
        await asyncScan(host, ports[prev..next])
        prev = next
    await asyncScan(host, ports[next..ports.len() - 1])
    
    

when isMainModule:
    let 
        host = "10.0.0.39"
        ports = toSeq(1..65535)

    asyncCheck asyncScanChunks(host, ports)
    echo "Done"
    echo "Open ", open.len()
    echo cpuTime()
    
