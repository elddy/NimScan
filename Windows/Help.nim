#[
    Helper
]#
import sequtils, strutils, parseopt, os, terminal

{.compile: "snifferWindows.c".}
{.passL: "-lws2_32".}
# {.passL: "-s".}

proc startSniffer*(target: cstring, portsToScan: ptr int, numberOfPorts: int, myIP: cstring): int {.importc: "startSniffer".}

type 
    stat* = enum
        open, closed, filtered, success, error, warning, info
    
    mode* = enum
        all, onlyOpen, openFiltered 
    
    SuperSocket* = ref object
        IP*: cstring
        ports*: seq[int]

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
    NimScan.exe -p:<portX>-<portY> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    NimScan.exe -p:<port> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    NimScan.exe -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    NimScan.exe (-h | --help)
Options:
    -h --help         Show this screen.
    -p                Ports to scan.
    --timeout=<time>  Timeout to add to the latency [default: 1000].
    --showAll         Show Open and Closed ports
        """

    when defined linux:
        echo """
NimScan.
Usage:
    ./NimScan -p:<portX>-<portY> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    ./NimScan -p:<port> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    ./NimScan -p:<port1>,<port2>,<portN> <host> [--timeout=<time>] [-f | -a] [--files=<number_of_file_descriptors>]
    ./NimScan (-h | --help)
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

proc validateOpt*(host: var string, ports: var seq[int], timeout: var int, numOfThreads: var int, fileDis: var int) =
    var 
        p = initOptParser(commandLineParams())
        timeoutSetted = false
        threadsSetted = false
        filteredSetted = false
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            try:
                if p.key.toLower() == "p":
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
                elif p.key.toLower() == "timeout":
                    timeoutSetted = true
                    timeout = (p.val).parseInt()
                elif p.key.toLower() == "a":
                    current_mode = all
                elif p.key.toLower() == "f":
                    filteredSetted = true
                    current_mode = openFiltered
                elif p.key.toLower() == "t":
                    threadsSetted = true
                    numOfThreads = (p.val).parseInt()
                elif p.key.toLower() == "files":
                    fileDis = (p.val).parseInt()
                    if fileDis > 10000:
                        printC(warning, "Max file descriptors per thread -> 10000")
                        fileDis = 10000
                else:
                    printHelp()
                    quit(-1)
            except:
                printHelp()
                quit(-1)
        of cmdArgument:
            host = p.key
    if filteredSetted and (timeoutSetted or threadsSetted):
        printC(error, "Can't use filtered mode (-f) with custom timeout (--timeout) or custom number of threads (-t)")
        quit(-1)

