#[
    Nim Port Scanner
]#

when defined windows:
    import modules/windows_sniffer

import modules/[globals, param_parser, scanner]
import os, net, nativesockets

proc main() =
    ## Main
    var 
        hosts: seq[string]
        ports: seq[int]
    
    validateOpt(hosts, ports, timeout, maxThreads, file_discriptors_number)

    if hosts.len == 1 and not isIpAddress($hosts[0]):
        hosts.add(getHostByName($hosts[0]).addrList[0])
        printC(info, "Target IP -> " & $hosts[0])

    if current_mode == mode.all:
        ## In filtered mode use rawsockets
        printC(warning, "In rawsockets mode")
        
        if ports.len > 10000 or file_discriptors_number > 5000:
            printC(warning, "More than 10,000 ports or 5,000 file descriptors in raw sockets mode may produce unreliable results")
        
        when defined windows:
            add_rule() ## Add firewall rule for raw sockets

        var 
            sniffer: Thread[SuperSocket]
            supSocket: SuperSocket

        for host in hosts:
            supSocket = SuperSocket(IP: host, ports: ports)
            createThread(sniffer, sniffer_thread, supSocket)
            sleep(500)
            
            startScanner(host, ports) ## Start scanning
        
        when defined windows:
            remove_rule() ## Remove firewall rule
        
    else:
        ## In default mode use normal async scan
        for host in hosts:
            startScanner(host, ports) ## Start scanning

    echo ""

when isMainModule:
    main()