#[
    Nim Port Scanner
]#
import Help
import asyncdispatch, asyncnet, times, sequtils, random, nativesockets, os

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
    let sock = newAsyncSocket()
    inc current_open_files
    try:
        if await withTimeout(sock.connect(ip, port.Port), timeout):
            openPorts[port] = port
            printC(stat.open, $port)    
        else:
            openPorts[port] = -1
        sock.close()
        dec current_open_files
    except:
        discard
    
proc startScan(ip: string, port_seq: seq[int]) {.async.} =
    for port in port_seq:
        inc scanned
        asyncCheck scan(ip, port)
        if current_mode == openFiltered:
            await sleepAsync(timeout / 1000000)
    drain(timeout)
    
proc threadScanner(supSocket: SuperSocket) {.thread.} =
    var
        host = supSocket.IP
        port_seq = supSocket.ports
    shuffle(port_seq)
    waitFor startScan($host, port_seq)

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

    echo "Number of file discriptors in a moment: ", file_discriptors_number
    echo "Div: ", division
    echo "Max number of threads: ", thr.len
    echo "Timeout: ", timeout
    echo "Mode: ", current_mode

    ## Start time
    let currentTime = getTime().toUnix()

    for ports in scan_ports.distribute(division):
        block current_ports:
            while true:
                for i in low(thr)..high(thr):
                    when defined linux:
                        if current_open_files > file_discriptors_number:
                            break
                    if not thr[i].running:
                        # echo "Thread: ", i ## Debug
                        let supSocket = SuperSocket(IP: host, ports: ports)    
                        createThread(thr[i], threadScanner, supSocket)
                        break current_ports
                    sleep(1)

    thr.joinThreads()

    ## End time
    echo "Done async + multithreading in: ", getTime().toUnix() - currentTime, " Seconds"


when isMainModule:
    var 
        host: string
        ports: seq[int]

    validateOpt(host, ports, timeout, maxThreads, file_discriptors_number)

    ## Validate options
    if host == "" or ports == @[]:
        printHelp()
        quit(-1)

    ## Main scanner
    main(host, ports)

    # timeout = 1
    # maxThreads = 1
    # file_discriptors_number = 5000

    var res = toSeq(openPorts)
    res = filter(res, proc (x: int): bool = x > 0)
    echo "Number of open ports: ", res.len()
    echo "Scanned: ", scanned
            
            

    