#[
    Helper
]#
import sequtils, strutils, parseopt, os, terminal

when defined windows:
    {.compile: "snifferWindows.c".}
    {.passL: "-lws2_32".}
    {.passL: "-s".}

    proc startSniffer*(target: cstring, portsToScan: ptr int, numberOfPorts: int, myIP: cstring, timeout: int): int {.importc: "startSniffer".}

type 
    stat* = enum
        open, closed, filtered, success, error, warning, info
    
    mode* = enum
        all, onlyOpen 
    
    SuperSocket* = object
        IP*: cstring
        ports*: seq[int]

    rawSocket* = object
        IP*: cstring
        ports*: seq[int]
        timeout*: int

var
    current_mode*: mode = onlyOpen

#[
    Prints nice and all
]#
proc printC*(STATUS: stat, text: string) = 
    
    case STATUS
    of closed:
        stdout.write text
        stdout.styledWrite(fgRed, " Closed\n")
    of open:
        stdout.write text
        stdout.styledWrite(fgGreen, " Open\n")
    of filtered:
        stdout.write text
        stdout.styledWrite(fgYellow, " Filtered\n")
    of success:
        stdout.styledWrite(fgGreen, "[+] ")
        stdout.write text, "\n"
    of error:
        stdout.styledWrite(fgRed, "[-] ")
        stdout.write text, "\n"
    of warning:
        stdout.styledWrite(fgYellow, "[!] ")
        stdout.write text, "\n"
    of info:
        stdout.styledWrite(fgBlue, "[*] ")
        stdout.write text, "\n"

proc printHelp*() =
    when defined windows:
        echo """
NimScan.

Usage:
    nimscan.exe -p:<portX>-<portY> <host> [--timeout:<time>] [-f:<limit of file descriptors>] [-t:<number of threads>] [-a]
    nimscan.exe -p:<port> <host>
    nimscan.exe -p:<port1>,<port2>,<portN> <host>
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -a, --all             Use rawsockets to find filtered/closed/open ports (Takes longer and limited to 10,000 ports).       
    -t, --threads         Number of threads per scan.
    -f, --files           File descriptors per thread limit.
    --timeout             Timeout to add to the latency [default: 1500].
    """

    when defined linux:
        echo """
NimScan.
Usage:
    ./NimScan -p:<portX>-<portY> <host> [--timeout=<time>] [--files=<limit of file descriptors>] [-a]
    ./NimScan -p:<port> <host>
    ./NimScan -p:<port1>,<port2>,<portN> <host>
    ./NimScan (-h | --help)
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -a, --all             Use rawsockets to find filtered/closed/open ports (Takes longer and limited to 10,000 ports).       
    -t, --threads         Number of threads per scan.
    -f, --files=<limit>   File descriptors per thread limit.
    --timeout=<time>      Timeout to add to the latency [default: 1500].
    """

proc validatePort(port: int) =
    if port < 1 or port > 65535:
        echo "Not valid port number, Port range: 0 < port < 65536"
        quit(-1)

proc validateOpt*(host: var string, ports: var seq[int], timeout: var int, numOfThreads: var int, fileDis: var int) =
    var 
        p = initOptParser(commandLineParams())
        timeoutSetted = false
        threadsSetted = false
        allSetted = false
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            try:
                case p.key.toLower()
                of "p", "ports", "port":
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
                of "timeout":
                    timeoutSetted = true
                    timeout = (p.val).parseInt()
                of "a", "all":
                    allSetted = true
                    current_mode = all
                of "f", "files":
                    fileDis = (p.val).parseInt()
                    if fileDis > 10000:
                        printC(warning, "Max file descriptors per thread -> 10000")
                        fileDis = 10000
                of "t", "threads":
                    threadsSetted = true
                    numOfThreads = (p.val).parseInt()
                of "h", "--help":
                    printHelp()
                    quit(-1)
                else:
                    printHelp()
                    quit(-1)
            except:
                printHelp()
                quit(-1)
        of cmdArgument:
            host = p.key
    if allSetted and (timeoutSetted or threadsSetted):
        printC(error, "Can't use all mode (-a | --all) with custom timeout (--timeout) or custom number of threads (-t | --threads)")
        quit(-1)

