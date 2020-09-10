#[
    Nim Port Scanner export for C/C++
    nim c -d:release --noMain --header --deadCodeElim:on --app:lib -o:NimScanToC.so NimScanToC.nim
]#

when defined windows:
    import ../modules/windows_sniffer

import ../modules/[globals, param_parser, scanner]
import os, net, nativesockets

proc scan(ip: cstring, scan_ports: openArray[cint]) {.exportc, dynlib.} =
    var 
        host = $ip
        ports: seq[int]
    for p in scan_ports:
        ports.add(p.int)
    startScanner(host, ports)

proc scanner(hostC: cstring, portsC: openArray[cint], commandLine: cstring) {.exportc, dynlib.} =
    var 
        host = $hostC
        ports: seq[int]
        # myTimeout = timeoutC.int
        # myMaxThreads = maxThreadsC.int
        # myfdn = fdnC.int
        # myMode = modeC.int

    for p in portsC:
        ports.add(p.int)

    validateOptC(host, ports, $commandLine)

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
        
        startScanner(host, ports) ## Start scanning
        
        when defined windows:
            remove_rule() ## Remove firewall rule

    else:
        ## In default mode use normal async scan
        startScanner(host, ports) ## Start scanning

    ## Print results
    printC(stat.open, $countOpen & " ports")

    if current_mode == mode.all:
        printC(closed, $countClosed & " ports")
        printC(filtered, $(ports.len - (countOpen + countClosed)))

    echo ""