#[
    Help
]#

proc printHelp*() =
    when defined windows:
        echo """
NimScan.

Usage:
    nimscan.exe -p:<portX>-<portY> <host> [--timeout:<time>] [-f:<limit of file descriptors>] [-t:<number of threads>] [-a]
    nimscan.exe -p:<port> <host>
    nimscan.exe -p:<port1>,<port2>,<portN> <host>
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -a, --all             Use rawsockets to find filtered/closed/open ports (Takes longer and limited to 10,000 ports).
    -t, --threads         Number of threads per scan.
    -f, --files=<limit>   File descriptors per thread limit.
    -i, --ignore          Ignore ping latency check.
    -v, --verbose         Verbose mode.
    -o, --output          CSV for output (default: result.csv)
    --os                  SMB-OS-Discovery (Nim-OSDiscovery)
    --timeout=<time>      Timeout to add to the latency [default: 1500].
    """

    when defined linux:
        echo """
NimScan.
Usage:
    NimScan -p:<portX>-<portY> <host> [--timeout=<time>] [--files=<limit of file descriptors>] [-a]
    NimScan -p:<port> <host>
    NimScan -p:<port1>,<port2>,<portN> <host>
    NimScan (-h | --help)
Options:
    -h, --help            Show this screen.
    -p, --ports           Ports to scan. [default: 1-65,535]
    -t, --threads         Number of threads per scan.
    -f, --files=<limit>   File descriptors per thread limit.
    -i, --ignore          Ignore ping latency check.
    -v, --verbose         Verbose mode.
    -o, --output          CSV for output (default: result.csv)
    --os                  SMB-OS-Discovery (Nim-OSDiscovery)
    --timeout=<time>      Timeout to add to the latency [default: 1500].
    """
