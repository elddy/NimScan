#[
    Output to CSV
]#

import strutils, os, globals

type Scan = object
    ip, hostname, latency, os_discovery: string
    openPorts, closedPorts, filteredPorts: seq[int]
    openCount, closedCount, filteredCount: int

proc toCsv*(ip, hostname, latency: string, openPorts, closedPorts, filteredPorts: seq[int], fileName: var string, os_discovery: string) =
    var 
        scan: Scan
    scan.openPorts = openPorts
    scan.closedPorts = closedPorts
    scan.filteredPorts = filteredPorts
    scan.ip = ip
    scan.hostname = hostname
    scan.latency = latency

    scan.openCount = openPorts.len
    scan.closedCount = closedPorts.len
    scan.filteredCount = filteredPorts.len
    scan.os_discovery = os_discovery

    if (not fileExists(fileName)):
        let csv = open(fileName, fmWrite)
        let header = ["#IP#", "#Hostname#", "#Latency#", "#OS_Discovery#", "#Open_ports#", "#Open#", "#Closed#", "#Filtered#"]
        csv.writeLine(header.join(","))
        csv.close()

    let csv = open(fileName, fmAppend)
    defer: csv.close()
    let 
        hostinfo = [ip, hostname, latency, os_discovery]
        padding_info = ["", "", "", ""]
        count_info = [scan.openCount, scan.closedCount, scan.filteredCount]
    csv.write(hostinfo.join(","))

    var 
        ports_line: seq[string]
        count = 0
    for i in 0..65535:
        ports_line = @[]
        try:
            ports_line.add($(scan.openPorts[i]))
        except:
            continue
        if count == 0:
            csv.writeLine("," & ports_line.join(",") & "," & count_info.join(","))
            inc count
        else:
            csv.writeLine(padding_info.join(",") & "," & ports_line.join(","))

    echo ""
    printC(info, "Results appended to file: " & fileName)