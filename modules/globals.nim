#[
    Globals
]#

import terminal

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
