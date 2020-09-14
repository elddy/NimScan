#[
    IP Segmentation
]#

import strutils, algorithm
when defined linux:
    from posix import inet_pton
when defined windows:
    import winim/inc/winsock

proc calc_range*(first: string, last: string): seq[string] = 
    var
        first_ipAddr: InAddr
        last_ipAddr: InAddr
        temp_ip: InAddr
    
    discard inet_pton(winsock.AF_INET, first, addr (first_ipAddr.S_addr))
    discard inet_pton(winsock.AF_INET, last, addr (last_ipAddr.S_addr))

    for i in ntohl(first_ipAddr.S_addr)..ntohl(last_ipAddr.S_addr):
        temp_ip.S_addr = i
        let ip = ($inet_ntoa(temp_ip)).split(".").reversed().join(".")
        result.add(ip)    
