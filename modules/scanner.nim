#[
    Scanner
]#

when defined windows:
    import windows_sniffer

import globals, latency
import asyncnet, asyncdispatch, net
import random, sequtils, os, strutils, times

randomize()

#[
    Async connect with timeout
]#
proc connect(ip: string, port: int) {.async.} =
    var sock = newAsyncSocket()
    try:
        if await withTimeout(sock.connect(ip, port.Port), timeout):
            openPorts[port] = port
            printC(stat.open, $port)
            inc countOpen
    except:
        discard
    finally:
        try:
            sock.close()
        except:
            discard

#[
    Scan ports chunck
]#    
proc scan(ip: cstring, port_seq: seq[int]) {.async.} =
    var sockops = newseq[Future[void]](port_seq.len)
    for i in 0..<port_seq.len:
        sockops[i] = connect($ip, port_seq[i])
        when defined windows:
            if current_mode == mode.all:
                ## In all mode
                await sleepAsync(timeout / 10000)
    waitFor all(sockops)

#[
    Scan thread
]#    
proc scan_thread(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports

    shuffle(port_seq) ## Shuffle ports order
    waitFor scan(host, port_seq)

#[
    Sniffer thread
]#
proc sniffer_thread*(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports
    when defined windows:
        start_sniffer(host, port_seq.toOpenArray(0, port_seq.len() - 1))

#[
    Scanner per host
]#
proc startScanner*(host: cstring, scan_ports: seq[int]) =
    var 
        thr: seq[Thread[SuperSocket]]
        thread: Thread[SuperSocket]
        currentTime: int64
    
    printC(info, "Scanning -> " & $host)

    for i in 1..maxThreads:
        thr.add(thread)
    
    for p in scan_ports:
        openPorts[p] = -1

    if not ignoreAlive:
        let ms = measure_latency($host)
        if ms == -1:
            printC(warning, "$1 does not respond to ping" % [$host])
        else:
            timeout = timeout + ms
    toScan = scan_ports.len

    printC(stat.info, "Number of threads -> " & $maxThreads)
    printC(stat.info, "Number of file discriptors per thread -> " & $(scan_ports.len / division).toInt())
    printC(stat.info, "Timeout: " & $timeout & "ms")
    
    currentTime = getTime().toUnix() ## Start time

    for ports in scan_ports.distribute(division):
        block current_ports:
            while true:
                for i in low(thr)..high(thr):
                    if not thr[i].running:
                        let supSocket = SuperSocket(IP: host, ports: ports)    
                        createThread(thr[i], scan_thread, supSocket)
                        sleep(timeout)
                        break current_ports
                    sleep(1)

    thr.joinThreads()

    echo ""
    for p in scan_ports:
        if openPorts[p] == rawStat.CLOSED.int and countClosed <= 20:
            printC(stat.closed, $p)
        elif openPorts[p] == rawStat.FILTERED.int and (scan_ports.len - (countOpen + countClosed)) <= 20:
            printC(stat.filtered, $p)

    printC(info, "Done scanning " & $host & " in: " & $(getTime().toUnix() - currentTime) & " Seconds\n") ## End time
    
    ## Print results
    printC(stat.open, $countOpen & " ports")

    if current_mode == mode.all:
        printC(closed, $countClosed & " ports")
        printC(filtered, $(scan_ports.len - (countOpen + countClosed)))
    echo ""

    ## Reset after every scan
    for i in 1..65535:
        openPorts[i] = 0 
    countClosed = 0
    countOpen = 0
