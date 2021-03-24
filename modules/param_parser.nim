#[
    Param parser
]#

import globals, help, ip_seg
import parseopt, strutils, os, sequtils, net

when defined linux:
    import posix
    proc validateRlimit*(fds: int) =
        var 
            rlimit = RLimit()
        
        discard getrlimit(RLIMIT_NOFILE, rlimit)
        var
            curr_lim = rlimit.rlim_cur
            max_lim = rlimit.rlim_max
        
        if fds > max_lim:
            printC(error, "Maximum file descriptor limit -> " & $max_lim)
            quit(-1)


proc validatePort(port: int) =
    if port < 1 or port > 65535:
        printC(error, "Not valid port number, Port range: 0 < port < 65536")
        quit(-1)

proc validateOpt*(hosts: var seq[string], ports: var seq[int], timeout: var int, numOfThreads: var int, fileDis: var int) =
    var 
        p = initOptParser(commandLineParams())
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
                    timeout = (p.val).parseInt()
                of "a", "all":
                    allSetted = true
                    current_mode = mode.all
                of "f", "files":
                    fileDis = (p.val).parseInt()
                    when defined linux:
                        validateRlimit(fileDis)
                of "t", "threads":
                    threadsSetted = true
                    numOfThreads = (p.val).parseInt()
                of "i", "ignore":
                    ## Don't send ping
                    ignoreAlive = true
                    printC(info, "Not sending pings (-i | --ignore)\n")
                of "v", "verbose":
                    ## Verbose mode
                    verbose = true
                    printC(info, "In verbose mode (-v | --verbose)\n")
                of "o", "out", "output":
                    ## Output to CSV
                    csvFile = (p.val)
                    if csvFile == "":
                        csvFile = "results.csv"
                    if splitFile(csvFile).ext != ".csv":
                        csvFile = csvFile & ".csv"
                    printC(info, "Output file: " & csvFile & "\n")
                    output = true
                of "os":
                    ## SMB-OS-Discovery
                    os_discovery = true
                    ports.add(445)
                of "h", "help":
                    printHelp()
                    quit(-1)
                else:
                    printHelp()
                    quit(-1)
            except:
                printHelp()
                quit(-1)
        of cmdArgument:
            if (p.key).contains(","):
                for p in (p.key).split(","):
                    hosts.add(p)

            elif (p.key).contains("-"):
                let 
                    range1 = (p.key).split("-")[0]
                    range2 = (p.key).split("-")[1]
                if isIpAddress(range1) and isIpAddress(range2):
                    hosts = calc_range(range1, range2)
                else:
                    hosts.add(p.key)
            elif (p.key).contains("/"):
                hosts = calc_range(p.key)
            else:
                hosts.add(p.key)

    ## Validate options
    if allSetted and threadsSetted:
        printC(error, "Can't use all mode (-a | --all) with custom number of threads (-t | --threads)")
        quit(-1)
    
    elif hosts.len == 0:
        printHelp()
        quit(-1)

    elif ports == @[]:
        ports = toSeq(1..65535)
        if current_mode == mode.all:
            ports = toSeq(1..10000)
            
    ports = deduplicate(ports)
    division = (ports.len() / fileDis).toInt()
    
    if division == 0:
        division = 1

proc validateOptC*(host: var string, ports: var seq[int], commandLine: string) =
    ## Parser for C export
    var 
        p = initOptParser(commandLine)
        threadsSetted = false
        allSetted = false
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            try:
                case p.key.toLower()
                of "timeout":
                    timeout = (p.val).parseInt()
                of "a", "all":
                    allSetted = true
                    current_mode = mode.all
                of "f", "files":
                    file_discriptors_number = (p.val).parseInt()
                    when defined linux:
                        validateRlimit(file_discriptors_number)
                of "t", "threads":
                    threadsSetted = true
                    maxThreads = (p.val).parseInt()
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
            discard

    ## Validate options
    if allSetted and threadsSetted:
        printC(error, "Can't use all mode (-a | --all) with custom number of threads (-t | --threads)")
        quit(-1)
    
    elif host == "":
        printHelp()
        quit(-1)

    elif ports == @[]:
        ports = toSeq(1..65535)
        if current_mode == mode.all:
            ports = toSeq(1..10000)
    
    division = (ports.len() / file_discriptors_number).toInt()
    
    if division == 0:
        division = 1
