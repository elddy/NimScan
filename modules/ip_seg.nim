#[
    IP Segmentation
]#

import strutils, algorithm
when defined linux:
    import posix
when defined windows:
    import winim/inc/winsock
    import winim

proc calc_range*(first: LPCSTR, last: string): seq[string] =
    var
        first_ipAddr: InAddr
        last_ipAddr: InAddr
        temp_ip: InAddr

    when defined windows:
        discard inet_pton(AF_INET, first, addr (first_ipAddr.S_addr))
        discard inet_pton(AF_INET, last, addr (last_ipAddr.S_addr))
        
        for i in ntohl(first_ipAddr.S_addr)..ntohl(last_ipAddr.S_addr):
            temp_ip.S_addr = i
            let ip = ($inet_ntoa(temp_ip)).split(".").reversed().join(".")
            result.add(ip)

    when defined linux:
        discard inet_pton(AF_INET, first, addr (first_ipAddr.s_addr))
        discard inet_pton(AF_INET, last, addr (last_ipAddr.s_addr))

        for i in ntohl(first_ipAddr.s_addr)..ntohl(last_ipAddr.s_addr):
            temp_ip.s_addr = i
            let ip = ($inet_ntoa(temp_ip)).split(".").reversed().join(".")
            result.add(ip)


proc calc_range*(subnet: string): seq[string] =
    var
        first = subnet.split("/")[0].split(".")
        mask = subnet.split("/")[1]
        netmask: seq[string]
        last: seq[string]
    
    let 
        full = (mask.parseInt() / 8).int
        remain = mask.parseInt() mod 8

    for i in 0..full-1:
        netmask.add("255")
    
    var bin: string
    for i in 0..remain-1:
        bin.add("1")
    if bin.len < 8:
        for i in 1..(8 - bin.len):
            bin.add("0")

    netmask.add($(bin.parseBinInt()))
    for i in 3..netmask.len:
        netmask.add("0")

    for i in 0..3:
        if netmask[i] == "255":
            last.add(first[i])
        else:
            last.add($(255 - netmask[i].parseInt()))
    
    last[3] = $(last[3].parseInt() - 1)
        
    result = calc_range(first.join("."), last.join("."))

when isMainModule:
    echo calc_range("192.168.1.1/25")