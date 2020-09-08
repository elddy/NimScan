#[
    Nim Port Scanner
]#

when defined windows:
    import modules/windows_sniffer

import modules/[globals, param_parser, scanner]
import times, sequtils, os, net, nativesockets

proc main() =
    ## Main
    var 
        host: string
        ports: seq[int]
        currentTime: int64
    
    validateOpt(host, ports, timeout, maxThreads, file_discriptors_number)

    if not isIpAddress host:
        host = getHostByName(host).addrList[0]
        printC(info, "Target IP -> " & host) 


    if current_mode == mode.all:
        ## In filtered mode use rawsockets
        printC(warning, "In rawsockets mode")
        
        if ports.len > 10000 or file_discriptors_number > 5000:
            printC(warning, "More than 10,000 ports or 5,000 file descriptors in raw sockets mode may produce unreliable results")
        
        when defined windows:
            add_rule() ## Add firewall rule for raw sockets

        var 
            sniffer: Thread[SuperSocket]
            supSocket = SuperSocket(IP: host, ports: ports)
        createThread(sniffer, sniffer_thread, supSocket)
        sleep(500)
        
        currentTime = getTime().toUnix() ## Start time

        startScanner(host, ports) ## Start scanning

        joinThread(sniffer) ## Wait join sniffer thread
        
        when defined windows:
            remove_rule() ## Remove firewall rule

    else:
        ## In default mode use normal async scan
        currentTime = getTime().toUnix() ## Start time

        startScanner(host, ports) ## Start scanning
        
    var res = toSeq(openPorts)
    res = filter(res, proc (x: int): bool = x > 0)
    echo "Number of open ports: ", res.len()
    
    printC(success, "Done scanning in: " & $(getTime().toUnix() - currentTime) & " Seconds\n") ## End time

when isMainModule:
    main()