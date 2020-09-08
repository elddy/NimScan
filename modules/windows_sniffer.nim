#[
    Windows Sniffer
]#

import globals
import osproc, strutils, os

{.compile: "snifferWindows.c".}
{.passL: "-lws2_32".}

proc startSniffer*(target: cstring, portsToScan: ptr int, numberOfPorts: int, myIP: cstring): int {.importc: "startSniffer".}

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
