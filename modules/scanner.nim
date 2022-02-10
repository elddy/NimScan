#[
    Scanner
]#

when defined windows:
    import windows_sniffer

import OSDiscovery
import globals, latency, toCsv
import asyncnet, asyncdispatch, net, nativesockets
import random, sequtils, os, strutils, times, terminal

randomize()

#[
    Async connect with timeout
]#
proc connect(ip: string, port: int) {.async.} =
    var sock = newAsyncSocket()
    try:
        if await withTimeout(sock.connect(ip, port.Port), timeout):
            openPorts[port] = port
            printPort(stat.open, ip, port)
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
    if not isIpAddress($host):
        try:
            host = getHostByName($host).addrList[0]
        except:
            host = cstring""
    when defined windows:
        start_sniffer(host, port_seq.toOpenArray(0, port_seq.len() - 1))

#[
    Scanner per host
]#
proc startScanner*(host: cstring, scan_ports: seq[int]) =
    var 
        thr: seq[Thread[SuperSocket]] = newSeq[Thread[SuperSocket]](maxThreads)
        countFiltered: int
        ip: string
        hostname: string
        ms: int
        os_info: TARGET_INFO
    
    if isIpAddress($host):
        ip = $host
    else:
        ## Resolve Name
        hostname = $host
        try:
            ip = getHostByName(hostname).addrList[0]
        except:
            printC(error, "Unable to resolve " & hostname)
            return
    
    for p in scan_ports:
        openPorts[p] = -1

    if not ignoreAlive:
        ## Initial checks not ignored
        ms = measure_latency(ip)
        if ms == -1:
            if verbose:
                printC(warning, "$1 does not respond to ping" % [ip])
            return
        else:
            # printC(success, "$1 responded to ping: $2ms\n" % [$host, $ms])
            timeout = timeout + ms
        
        if hostname == "":
            ## Resolve IP
            try:
                hostname = getHostByAddr(ip).name
            except:
                hostname = ""
    
    toScan = scan_ports.len

    if verbose:
        printHeader(ip, hostname, ms) ## Header

    for ports in scan_ports.distribute(division):
        ## Start scanning
        block current_ports:
            while true:
                # printCurrentScan($host)
                for i in low(thr)..high(thr):
                    if not thr[i].running:
                        let supSocket = SuperSocket(IP: ip, ports: ports)
                        createThread(thr[i], scan_thread, supSocket)
                        # sleep(timeout)
                        break current_ports   
                sleep(1)

    thr.joinThreads()
    
    if openPorts[445] == 445 and os_discovery:
        os_info = runOSDiscovery(ip, timeout)
        printOSInfo(os_info)

    for p in scan_ports:
        if openPorts[p] == rawStat.CLOSED.int and countClosed <= 20:
            printPort(stat.closed, ip, p)
        elif openPorts[p] == rawStat.FILTERED.int and (scan_ports.len - (countOpen + countClosed)) <= 20:
            printPort(stat.filtered, ip, p)

    if current_mode == mode.all:
        countFiltered = scan_ports.len - (countOpen + countClosed)
    else:
        countClosed = scan_ports.len - countOpen

    if verbose:
        printFooter(countOpen, countClosed, countFiltered, $host) ## Print footer (results)

    var
        all_open, all_closed, all_filtered: seq[int]

    for i in 1..65535:
        if current_mode == mode.all:
            if openPorts[i] == rawStat.CLOSED.int:
                all_closed.add(i)
            elif openPorts[i] == rawStat.FILTERED.int:
                all_filtered.add(i)
        else:
            if openPorts[i] == 0:
                all_closed.add(i)
        if openPorts[i] == i:
            all_open.add(i)
    
    if output:
        ## Output results to CSV
        let latency = $ms & "ms"
        toCsv(ip, hostname, latency, all_open, all_closed, all_filtered, csvFile, os_info.os_version)

    ## Reset after every scan
    for i in 1..65535:
        openPorts[i] = 0 
    countClosed = 0
    countOpen = 0
