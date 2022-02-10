#[
    Globals
]#

when not (compiles do: import OSDiscovery):
    static: echo "No module: OSDiscovery, install via nimble:\n"
    static: echo "nimble install https://github.com/elddy/Nim-OSDiscovery\n"

import OSDiscovery
import terminal, strutils

type 
    stat* = enum ## Status
        open, closed, filtered, success, error, warning, info
    
    mode* = enum ## Mode (all = open/closed/filtered)
        all, onlyOpen 

    SuperSocket* = object ## Pass to threads
        IP*: cstring
        ports*: seq[int]

    rawStat* = enum
        FILTERED = 0, OPEN = 1, CLOSED = 2

var
    openPorts*: array[1..65535, int] ## Because seq is not GC-Safe
    countOpen* = 0
    countClosed* = 0

    ## Default ##
    current_mode*: mode = onlyOpen
    timeout* = 1500 
    file_discriptors_number* = 5000 
    maxThreads* = 1
    ignoreAlive* = false
    toScan* = 0
    current_open_files* = 0
    division* = 1 ## Division for port chuncks
    verbose* = false
    output* = false
    csvFile* = ""
    os_discovery* = false

#[
    Prints nice and all
]#
proc printC*(STATUS: stat, text: string) = 
    case STATUS
    of closed:
        stdout.write text
        stdout.styledWrite(fgRed, " Closed\n")
    of open:
        stdout.write text
        stdout.styledWrite(fgGreen, " Open\n")
    of filtered:
        stdout.write text
        stdout.styledWrite(fgYellow, " Filtered\n")
    of success:
        stdout.styledWrite(fgGreen, "[+] ")
        stdout.write text, "\n"
    of error:
        stdout.styledWrite(fgRed, "[-] ")
        stdout.write text, "\n"
    of warning:
        stdout.styledWrite(fgYellow, "[!] ")
        stdout.write text, "\n"
    of info:
        stdout.styledWrite(fgBlue, "[*] ")
        stdout.write text, "\n"

#[
    Prints header for every host
]#
proc printHeader*(ip, hostname: string, latency: int) =
    var 
        host = hostname
        lat: string
    if host == "" or host == ip:
        host = "N/A"
    if latency == -1:
        lat = "N/A"
    else:
        lat = $latency & "ms"
    let 
        ip_header = "IP: " & ip
        host_header = "Host: " & host
        latency_header = "Latency: " & lat
        header_len = ip_header.len + host_header.len + latency_header.len + 8
        underscore = repeat('_', header_len)
    
    echo " ", underscore                                       
    stdout.write("| IP: ")
    stdout.styledWrite(fgMagenta, ip)
    stdout.write(" | Host: ")
    stdout.styledWrite(fgMagenta, host)
    stdout.write(" | Latency: ")
    stdout.styledWrite(fgMagenta, lat)
    echo " |"
    echo ""

#[
    Prints port
]#
proc printPort*(STATUS: stat, ip: string, port: int) =
    let text = ip & ":"
    stdout.styledWrite(fgMagenta, "==> ")
    stdout.write(text); printC(STATUS, $port)

proc printCurrentScan*(ip: string) =
    stdout.write("--------> ")
    stdout.styledWrite(fgMagenta, ip)
    stdout.write(" <--------")
    stdout.flushFile

#[
    Prints footer for every host
]#
proc printFooter*(countOpen, countClosed, countFiltered: int, host: string) =
    let
        open_footer = "Open: " & $countOpen
        closed_footer = "Closed: " & $countClosed
        filtered_footer = "Filtered: " & $countFiltered
        header_len = open_footer.len + closed_footer.len + filtered_footer.len + 8
        equals = repeat('=', header_len)
    
    echo ""
    stdout.write("| Open: ")
    stdout.styledWrite(fgGreen, $countOpen)
    stdout.write(" | Closed: ")
    stdout.styledWrite(fgRed, $countClosed)
    stdout.write(" | Filtered: ")
    stdout.styledWrite(fgYellow, $countFiltered)
    echo " |"
    echo " ", equals
    echo ""

proc printOSInfo*(info: TARGET_INFO) =
    stdout.styledWrite(fgMagenta, "\n--------> "); stdout.write("SMB OS Discovery"); stdout.styledWrite(fgMagenta, " <--------\n\n")
    stdout.styledWrite(fgMagenta, "====| "); stdout.write("OS Version: "); stdout.styledWrite(fgCyan, info.os_version); stdout.write("\n")
    stdout.styledWrite(fgMagenta, "====| "); stdout.write("NetBIOS Domain Name: "); stdout.styledWrite(fgCyan, info.netBios_domain); stdout.write("\n")
    stdout.styledWrite(fgMagenta, "====| "); stdout.write("NetBIOS Computer Name: "); stdout.styledWrite(fgCyan, info.netBios_computer); stdout.write("\n")
    stdout.styledWrite(fgMagenta, "====| "); stdout.write("DNS Domain Name: "); stdout.styledWrite(fgCyan, info.dns_domain); stdout.write("\n")
    stdout.styledWrite(fgMagenta, "====| "); stdout.write("DNS Computer Name: "); stdout.styledWrite(fgCyan, info.dns_computer); stdout.write("\n\n")

proc printBanner*() =
    let banner1 = """ 
    )              (                      
 ( /(              )\ )                   
 )\()) (      )   (()/(         )         
((_)\  )\    (     /(_)) (   ( /(   (     
 _((_)((_)   )\  '(_))   )\  )(_))  )\ )  
"""
    let banner2 = """
| \| | (_) _((_)) / __| ((_)((_)_  _(_/(  
| .` | | || '  \()\__ \/ _| / _` || ' \)) 
|_|\_| |_||_|_|_| |___/\__| \__,_||_||_|                                        
    """
    let speech = """

    Fast Port Scanner Written In Nim
    """
    stdout.styledWrite(fgRed, banner1)
    stdout.styledWrite(fgYellow, banner2)
    stdout.styledWrite(fgYellow, speech)
    echo ""
