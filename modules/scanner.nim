#[
    Scanner
]#

when defined windows:
    ## Use C winsock raw socket sniffer
    import windows_sniffer

import globals, latency
import asyncnet, asyncdispatch, net
import random, sequtils, os, strutils, terminal

randomize()

#[
    Async connect with timeout
]#
proc connect(ip: string, port: int) {.async.} =
    var sock = newAsyncSocket()
    inc current_open_files
    try:
        if await withTimeout(sock.connect(ip, port.Port), timeout):
            openPorts[port] = port
            # stdout.eraseLine
            printC(stat.open, $port)
        else:
            openPorts[port] = -1
    except:
        discard
    finally:
        sock.close()

#[
    Scan ports chunck
]#    
proc scan(ip: string, port_seq: seq[int]) {.async.} =
    var sockops = newseq[Future[void]](port_seq.len)
    for i in 0..<port_seq.len:
        inc scanned
        sockops[i] = connect(ip, port_seq[i])
        if current_mode == mode.all:
            ## In all mode
            await sleepAsync(timeout / 500)
        # stdout.write(ip & " -> Scanned: " & $scanned & " from: " & $toScan & "\r")
    waitFor all(sockops)
    current_open_files = current_open_files - port_seq.len

#[
    Scan thread
]#    
proc scan_thread(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports

    shuffle(port_seq) ## Shuffle ports order
    waitFor scan($host, port_seq)

#[
    Sniffer thread
]#
proc sniffer_thread*(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports
    when defined windows:
        if startSniffer(host, addr port_seq[0], port_seq.len, $getPrimaryIPAddr()) == 1:
            printC(error, "Run as administrator")
            quit(-1)

#[
    Scanner per host
]#
proc startScanner*(host: var string, scan_ports: seq[int]) =
    var 
        thr: seq[Thread[SuperSocket]]
        thread: Thread[SuperSocket]
    
    for i in 1..maxThreads:
        thr.add(thread)
    
    let ms = measure_latency(host)
    if ms == -1:
        printC(warning, "$1 does not respond to ping" % [host])
    else:
        timeout = timeout + ms

    toScan = scan_ports.len

    printC(stat.info, "Number of threads -> " & $maxThreads)
    printC(stat.info, "Number of file discriptors per thread -> " & $(scan_ports.len / division).toInt())
    printC(stat.info, "Timeout: " & $timeout & "ms")
    
    for ports in scan_ports.distribute(division):
        block current_ports:
            while true:
                for i in low(thr)..high(thr):
                    if current_open_files >= file_discriptors_number:
                        break
                    elif not thr[i].running:
                        let supSocket = SuperSocket(IP: host, ports: ports)    
                        createThread(thr[i], scan_thread, supSocket)
                        break current_ports
                sleep(1)

    thr.joinThreads()
    echo ""
    printC(info, "Scanned: " & $scanned)
