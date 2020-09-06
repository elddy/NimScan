#[
    Nim Port Scanner
]#
import Help
import asyncdispatch, asyncnet, times, sequtils, random, nativesockets, os, net, strutils, osproc

var 
    openPorts: array[1..65535, int]
    ## Default ##
    timeout = 1500 
    file_discriptors_number = 4500 
    maxThreads = 1
    scanned = 0
    current_open_files = 0

randomize()

proc scan(ip: string, port: int) {.async.} =
    var sock = newAsyncSocket()
    inc current_open_files

    try:
        if await withTimeout(sock.connect(ip, port.Port), timeout):
            openPorts[port] = port
            if current_mode != openFiltered:
                printC(stat.open, $port)
        else:
            openPorts[port] = -1
    except:
        discard
    finally:
        sock.close()
    # dec current_open_files
    
proc startScan(ip: string, port_seq: seq[int]) {.async.} =
    for port in port_seq:
        inc scanned
        asyncCheck scan(ip, port)
        if current_mode == openFiltered:
            await sleepAsync(timeout / 10000)
    drain(timeout * 1000)
    current_open_files = current_open_files - port_seq.len
    
proc threadScanner(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports

    shuffle(port_seq)
    waitFor startScan($host, port_seq)

proc threadSniffer(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports

    if startSniffer(host, addr port_seq[0], port_seq.len, $getPrimaryIPAddr()) == 1:
        printC(error, "Run as administrator")
        quit(-1)

proc main(host: string, scan_ports: seq[int]) =
    var 
        thr: seq[Thread[SuperSocket]]
        thread: Thread[SuperSocket]
        division = (scan_ports.len() / file_discriptors_number).toInt()

    for i in 1..maxThreads:
        thr.add(thread)
    
    if division == 0:
        division = 1

    if current_mode == openFiltered:
        timeout = 1

    ## For debuging
    printC(stat.info, "Number of threads -> " & $maxThreads)
    printC(stat.info, "Number of file discriptors per thread -> " & $(scan_ports.len / division).toInt() & "\n")
    # echo "Timeout: ", timeout
    # echo "Mode: ", current_mode

    for ports in scan_ports.distribute(division):
        block current_ports:
            while true:
                for i in low(thr)..high(thr):
                    if current_open_files >= file_discriptors_number:
                        break
                    if not thr[i].running:
                        # echo "Thread: ", i ## Debug
                        let supSocket = SuperSocket(IP: host, ports: ports)    
                        createThread(thr[i], threadScanner, supSocket)
                        break current_ports
                    sleep(1)

    thr.joinThreads()

when isMainModule:
    var 
        host: string
        ports: seq[int]
        currentTime: int64
    
    validateOpt(host, ports, timeout, maxThreads, file_discriptors_number)

    ## Validate options
    if host == "":
        printHelp()
        quit(-1)

    if ports == @[]:
        ports = toSeq(1..65535)
    
    ## In filtered mode use rawsockets
    if current_mode == openFiltered:
        printC(warning, "In filtered mode")
        let addCommand = "netsh advfirewall firewall add rule name='NimScan' dir=in action=allow program=\"$1\" enable=yes" % [getAppFilename()]
        var (outC, errC) = execCmdEx(addCommand)
        if errC == 0:
            printC(success, "Added to firewall")
        else:
            printC(error, outC)
            quit(-1)
        var 
            thread: Thread[SuperSocket]
            supSocket = SuperSocket(IP: host, ports: ports) 
        createThread(thread, threadSniffer, supSocket)
        sleep(500)
        
        ## Start time
        currentTime = getTime().toUnix()

        ## Main scanner
        main(host, ports)
        echo "\nScanned: ", scanned
        ## Wait for the raw socket sniffer to finish
        joinThread(thread)

        let delCommand = "netsh advfirewall firewall delete rule name='NimScan'"
        (outC, errC) = execCmdEx(addCommand)
        if errC == 0:
            printC(success, "Removed from firewall\n")
        else:
            printC(error, outC)
            quit(-1)
    else:
        ## In default mode use normal async scan
        
        ## Start time
        currentTime = getTime().toUnix()

        ## Main scanner
        main(host, ports)
        
        var res = toSeq(openPorts)
        res = filter(res, proc (x: int): bool = x > 0)
        echo "Number of open ports: ", res.len()
        # echo "Scanned: ", scanned
    
    ## End time
    echo "Done scanning in: ", getTime().toUnix() - currentTime, " Seconds"

            
            

    