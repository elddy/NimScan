#[
    Latency
]#

import osproc, regex, strutils

#[
    Measure latency with ping command
]#
proc measure_latency*(ip: string): int =
    var 
        outp: string
        errC: int
        reg: RegexMatch
    when defined windows:
        (outp, errC) = execCmdEx("ping $1 -n 1" % [ip])
        if outp.find(re"time[<=]([\d\.]+)ms", reg):
            result = outp[reg.group(0)[0]].parseInt()
        else:
            result = -1
    when defined linux:
        (outp, errC) = execCmdEx("ping $1 -c 1" % [ip])
        if outp.find(re"time[<=]([\d\.]+).+ms", reg):
            result = outp[reg.group(0)[0]].parseFloat().toInt()
        else:
            result = -1
