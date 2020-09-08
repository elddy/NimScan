#[
    Param parser
]#

import globals, help
import parseopt, strutils, os, sequtils

proc validatePort(port: int) =
    if port < 1 or port > 65535:
        printC(error, "Not valid port number, Port range: 0 < port < 65536")
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
                    current_mode = mode.all
                of "f", "files":
                    fileDis = (p.val).parseInt()
                    if fileDis > 10000:
                        printC(warning, "Max file descriptors per thread -> 10000")
                        # fileDis = 10000
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
    
    ## Validate options
    if allSetted and (timeoutSetted or threadsSetted):
        printC(error, "Can't use all mode (-a | --all) with custom timeout (--timeout) or custom number of threads (-t | --threads)")
        quit(-1)
    
    elif host == "":
        printHelp()
        quit(-1)

    elif ports == @[]:
        ports = toSeq(1..65535)
        if current_mode == mode.all:
            ports = toSeq(1..10000)
    
    division = (ports.len() / fileDis).toInt()
    
    if division == 0:
        division = 1


