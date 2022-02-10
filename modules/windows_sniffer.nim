#[
    Windows Sniffer
]#

import globals
import osproc, strutils, os
from net import getPrimaryIPAddr

import winim except `$`
from winlean import inet_ntoa, InAddr

type
  IPV4_HDR {.bycopy.} = object
    ip_header_len {.bitsize: 4.}: char ##  4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    ip_version {.bitsize: 4.}: char ##  4-bit IPv4 version
    ip_tos: char            ##  IP type of service
    ip_total_length: cushort  ##  Total length
    ip_id: cushort            ##  Unique identifier
    ip_frag_offset {.bitsize: 5.}: char ##  Fragment offset field
    ip_more_fragment {.bitsize: 1.}: char
    ip_dont_fragment {.bitsize: 1.}: char
    ip_reserved_zero {.bitsize: 1.}: char
    ip_frag_offset1: char   ## fragment offset
    ip_ttl: char            ##  Time to live
    ip_protocol: char       ##  Protocol(TCP,UDP etc)
    ip_checksum: cushort      ##  IP checksum
    ip_srcaddr: cuint         ##  Source address
    ip_destaddr: cuint        ##  Source address

  TCP_HDR {.bycopy.} = object
    source_port: cushort      ##  source port
    dest_port: cushort       ##  destination port
    sequence: cuint           ##  sequence number - 32 bits
    acknowledge: cuint        ##  acknowledgement number - 32 bits
    ns {.bitsize: 1.}: char   ## Nonce Sum Flag Added in RFC 3540.
    reserved_part1 {.bitsize: 3.}: char ## according to rfc
    data_offset {.bitsize: 4.}: char ## The number of 32-bit words in the TCP header.
                                    ## 	This indicates where the data begins.
                                    ## 	The length of the TCP header is always a multiple
                                    ## 	of 32 bits.
    fin{.bitsize: 1.}: char  ## Finish Flag
    syn {.bitsize: 1.}: char  ## Synchronise Flag
    rst {.bitsize: 1.}: char  ## Reset Flag
    psh {.bitsize: 1.}: char  ## Push Flag
    ack {.bitsize: 1.}: char  ## Acknowledgement Flag
    urg {.bitsize: 1.}: char  ## Urgent Flag
    ecn {.bitsize: 1.}: char  ## ECN-Echo Flag
    cwr {.bitsize: 1.}: char  ## Congestion Window Reduced Flag
                            ## //////////////////////////////
    window: cushort           ##  window
    checksum: cushort         ##  checksum
    urgent_pointer: cushort   ##  urgent pointer

var 
    target: cstring

proc add_rule*() =
    let 
        addCommand = "netsh advfirewall firewall add rule name='NimScan' dir=in action=allow program=\"$1\" enable=yes" % [getAppFilename()]
        (outC, errC) = execCmdEx(addCommand)
    if errC != 0:
        printC(error, outC)
        quit(-1)

proc remove_rule*() =
    let 
        delCommand = "netsh advfirewall firewall delete rule name='NimScan'"
        (outC, errC) = execCmdEx(delCommand)
    if errC != 0:
        printC(error, outC)
        quit(-1)

proc check_port(tcpheader: TCP_HDR) =
    let src_port = ntohs(tcpheader.source_port)
    if tcpheader.ack.cuint == 1 and openPorts[src_port.int] == -1:
        ## Check response
        if tcpheader.rst.cuint == 1:
            ## RST-ACK -> Closed
            openPorts[src_port] = rawStat.CLOSED.int
            inc countClosed

proc PrintTcpPacket*(buffer: array[65536, char], size: int, iphdr: IPV4_HDR) =
    var ip_addr: winlean.InAddr
    ip_addr.s_addr = iphdr.ip_srcaddr
    if winlean.inet_ntoa(ip_addr) == target:
        var 
            iphdrlen = (iphdr.ip_header_len.int * 4)
            miniBuffer: array[65536, char]
        for i in 0..(size-1):
            miniBuffer[i] = buffer[iphdrlen+i]
        var tcpheader = cast[TCP_HDR](miniBuffer)
        check_port(tcpheader)

proc ProcessPacket(buffer: array[65536, char], size: int) =
    var iphdr = cast[IPV4_HDR](buffer)
    case iphdr.ip_protocol.int
    of 6:
        PrintTcpPacket(buffer,size,iphdr)
    else:
        discard

proc StartSniffing(snifferSocket: SOCKET) =
    var 
        buffer: array[65536, char]
        saddr: sockaddr
        saddr_size: int32 = sizeof(saddr).int32
        data_size: int32

    while true:
        data_size = recvfrom(snifferSocket, cast[ptr char](addr buffer), 65536.int32, 0.int32, addr saddr, addr saddr_size)
        if data_size > 0:
            buffer.ProcessPacket(data_size)
        else:
            printC(error, "recvfrom error: " & $GetLastError())
            quit(-1) 

proc start_sniffer*(ip: cstring, port_seq: openArray[int]) =
    target = ip
    var 
        wsa: WSADATA
        myIP = $(getPrimaryIPAddr().address_v4.join("."))

    if WSAStartup(MAKEWORD(2,2), &wsa) != 0:
        printC(error, "WSAStartup failed: " & $GetLastError())
        quit(-1)

    var 
        snifferSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        dest: sockaddr_in

    if snifferSocket == INVALID_SOCKET:
        printC(error, "Failed to create socket: " & $GetLastError())
        quit(-1)
    
    dest.sin_addr.S_addr = inet_addr(myIP)
    dest.sin_port = 0
    dest.sin_family = AF_INET

    if `bind`(snifferSocket, cast[(ptr sockaddr)](addr dest), sizeof(dest).int32) == SOCKET_ERROR:
        printC(error, "bind failed: " & $GetLastError())
        quit(-1)

    var 
        j = 1
        In: DWORD = 2

    if WSAIoctl(snifferSocket, (DWORD)SIO_RCVALL, &j, (DWORD)sizeof(j), NULL, 0, &In, NULL, NULL) == SOCKET_ERROR:
        printC(error, "WSAIoctl failed: " & $GetLastError())
        quit(-1)

    StartSniffing(snifferSocket)