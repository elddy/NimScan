#[
    Test
]#
import asyncdispatch, asyncnet, times, sequtils, threadpool, regex, strutils, osproc, parseopt, os, terminal

type 
    stat = enum
        open, closed
    mode = enum
        all, onlyOpen 

var 
    latency = 1000
    open_ports: array[1..65535, int]
    current_mode: mode = onlyOpen

#[
    Prints nice and all
]#
proc printC(STATUS: stat, text: string) = 
    stdout.write text
    case STATUS
    of closed:
        stdout.styledWrite(fgRed, " Closed\n")
    of open:
        stdout.styledWrite(fgGreen, " Open\n")

#[
    Measure latency with ping command
]#
proc measureLatency(ip: string): int =
    var 
        outp: string
        errC: int
        reg: RegexMatch
    echo "Measuring ping latency"
    when defined windows:
        (outp, errC) = execCmdEx("ping $1 -n 1" % [ip])
        if outp.find(re"time[<=]([\d\.]+)ms", reg):
            echo "Latency: ", outp[reg.group(0)[0]], "ms"
            result = outp[reg.group(0)[0]].parseInt()
        else:
            result = -1
    when defined linux:
        (outp, errC) = execCmdEx("ping $1 -c 1" % [ip])
        if outp.find(re"time[<=]([\d\.]+).+ms", reg):
            echo "Latency: ", outp[reg.group(0)[0]], "ms"
            result = outp[reg.group(0)[0]].parseFloat().toInt()
        else:
            result = -1

proc connect(host: string, p: int, timeout = latency) {.async.} =
    var client = newAsyncSocket()
    try:
        if await withTimeout(client.connect(host, p.Port), timeout):
            open_ports[p] = p
            printC(open, $p)
        elif current_mode == all:
            printC(closed, $p)
    except:
        discard
    finally:
        client.close()
    
proc getChunk(ports: seq[int], chunk: int): seq[int] =
    result = ports[..chunk]

proc scanPorts(host: string, ports: seq[int], chunkOfPorts: int) {.async.} =
    var 
        scannedPorts = 0
    for p in ports:
        asyncCheck connect(host, p)
        inc scannedPorts
        if scannedPorts == chunkOfPorts:
            drain(latency) # Every number chunkOfPorts, wait for events with latency timeout
            scannedPorts = 0
        await sleepAsync(1)

proc scanEveryChunk(host: string, ports: seq[int], chunkSizeForAsync: int) {.thread.} =
    waitFor scanPorts(host, ports, chunkSizeForAsync)

proc main(host: string, ports: seq[int]) =
    let 
        chunkSizeForThread = 10000 # Every 10,000 ports, create new thread
        chunkSizeForAsync = 5000 # Every 5,000 ports, wait for all async scan in every thread 
    var 
        checkingPorts = ports

    while checkingPorts.len > chunkSizeForThread:
        let chunkSeq = getChunk(checkingPorts, chunkSizeForThread)
        spawn scanEveryChunk(host, chunkSeq, chunkSizeForAsync)
        checkingPorts.delete(0, chunkSizeForThread - 1)
        
    spawn scanEveryChunk(host, checkingPorts, checkingPorts.len) # Passing the last piece of ports sequence and the length of the sequence
    sync()

proc printHelp() =
    when defined windows:
        echo """
Nim Port Scanner.

Usage:
    scanner.exe -p:<portX>-<portY> <host> [--timeout=<time>] [--showAll]
    scanner.exe -p:<port> <host> [--timeout=<time>] [--showAll] 
    scanner.exe -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [--showAll]
    scanner.exe (-h | --help)

Options:
    -h --help         Show this screen.
    -p                Ports to scan.
    --timeout=<time>  Timeout to add to the latency [default: 1000].
    --showAll         Show Open and Closed ports
        """

    when defined linux:
        echo """
Nim Port Scanner.

Usage:
    ./scanner -p:<portX>-<portY> <host> [--timeout=<time>] [--showAll]
    ./scanner -p:<port> <host> [--timeout=<time>] [--showAll]
    ./scanner -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [--showAll]
    ./scanner (-h | --help)

Options:
    -h --help         Show this screen.
    -p                Ports to scan.
    --timeout=<time>  Timeout added to latency [default: 1000].
    --showAll         Show Open and Closed ports
        """

proc validatePort(port: int) =
    if port < 1 or port > 65535:
        echo "Not valid port number, Port range: 0 < port < 65536"
        quit(-1)


proc validateOpt(host: var string, ports: var seq[int], timeout: var int) =
    var p = initOptParser(commandLineParams())
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            try:
                if p.key == "p":
                    if (p.val).contains(","):
                        for p in (p.val).split(","):
                            validatePort(p.parseInt())
                            ports.add(p.parseInt()) 

                    elif (p.val).contains("-"):
                        let 
                            range1 = (p.val).split("-")[0].parseInt()
                            range2 = (p.val).split("-")[1].parseInt()
                        validatePort(range1)
                        validatePort(range2)
                        ports = toSeq(range1..range2)

                    else:
                        validatePort((p.val).parseInt())
                        ports.add((p.val).parseInt())
                elif p.key == "timeout":
                    if (p.val).parseInt() < 1000:
                        echo "Timeout must be at least 1000ms"
                        quit(-1)
                    timeout = (p.val).parseInt()
                elif p.key == "showAll":
                    current_mode = all
                else:
                    printHelp()
                    quit(-1)
            except:
                printHelp()
                quit(-1)
        of cmdArgument:
            host = p.key

when isMainModule:

    var 
        host: string
        ports: seq[int]
        timeout = 1000 # Default

    validateOpt(host, ports, timeout)

    ## Validate options
    if host == "" or ports == @[]:
        printHelp()
        quit(-1)

    ## Latency measurement
    latency = measureLatency(host) + timeout # Timeout for each connection

    let currentTime = getTime().toUnix()
    
    ## Main scanner
    main(host, ports)

    var res = toSeq(open_ports)
    res = filter(res, proc (x: int): bool = x > 0)
    echo "Number of open ports: ", res.len()
    echo getTime().toUnix() - currentTime, " Seconds"
