import asyncnet, asyncdispatch, times, threadpool, osproc, strutils, regex, sequtils

var 
    interval = 500
    open_ports: array[1..65535, int]

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
        (outp, errC) = execCmdEx("ping $1 -t 1" % [ip])
        if outp.find(re"time[<=]([\d\.]+)ms", reg):
            echo "Latency: ", outp[reg.group(0)[0]], "ms"
            result = outp[reg.group(0)[0]].parseFloat()
        else:
            result = -1
    
proc try_connect(sock: AsyncSocket, IP: string, port: int) {.async.} =
    let fut = sock.connect(IP, port.Port)
    if waitFor withTimeout(fut, interval):
        open_ports[port] = port

proc scan_single(port: int, host: cstring) {.thread.} =
    let sock: AsyncSocket = newAsyncSocket()
    asyncCheck sock.try_connect($host, port)
    sock.close()

proc scanPorts(ports: seq[int], host: cstring): seq[int] =
    var realPorts: seq[int]
    for p in ports:
        spawn scan_single(p, host)
    sync()
    for p in open_ports:
        if p != 0:
            realPorts.add(p)
    result = realPorts

when isMainModule:
    let 
        host = "10.0.0.39"
        ports = toSeq(1..65535)
        checkInterval = measureLatency(host)
    if checkInterval != -1:
        interval = checkInterval + 20
    echo "Timeout: ", $interval, "ms"
    for op in scanPorts(ports, host):
        echo $op, " is open"
    echo cpuTime()