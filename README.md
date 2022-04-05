[![Coverage](https://codecov.io/gh/marcolussetti/scannerofcerts/branch/add-tests/graphs/badge.svg?branch=add-tests)](https://codecov.io/gh/marcolussetti/scannerofcerts)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](https://tldrlegal.com/license/apache-license-2.0-(apache-2.0))
[![golangci-lint](https://github.com/marcolussetti/scannerofcerts/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/marcolussetti/scannerofcerts/actions/workflows/golangci-lint.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/marcolussetti/scannerofcerts)](https://goreportcard.com/report/github.com/marcolussetti/scannerofcerts)
-----
# scannerofcerts

`scannerofcerts` is a Go utility to scan one or more ranges to detect SSL certificates.

Given an IP range, it will scan it for open SSL-associated ports, and report to a CSV file (or standard output) 
the results.

## Installation

`scannerofcerts` requires the libpcap library to be installed. Other than that, it is a single binary distributed through the
[_Release_](https://github.com/marcolussetti/scannerofcerts/releases) section here on GitHub.

### Linux
Install libpcap (Ubuntu/Debian: `sudo apt install libpcap`, Arch: `sudo pacman -S libpcap`, RHEL/Fedora/OracleLinux/RockyLinux: `sudo yum install libpcap`, etc.)

Download and run the latest `scannerofcerts` binary for amd64 from the releases section.

### Windows

Install npcap in WinPCap compatibility mode:
- Download and run "Npcap 1.55 installer" (or later version) from https://nmap.org/npcap/
- When asked if wished to retain WinPCap compatibility mode, please choose yes

Download and run the latest `scannerofcerts` exe for amd64.

### Mac

Currently, the build pipeline is failing to dynamically link libpcap on Mac. Current process:
- Install libpcap with your favourite package manager (`brew install libpcap`)
- Install golang (see instructions and package at https://golang.org/doc/install)
- Clone this repo (`git clone https://github.com/marcolussetti/scannerofcerts.git`)
- Build this repo (`go build -o scannerofcerts ./cmd/scannerofcerts`)
- Run the binary (`chmod +x scannerofcerts && ./scannerofcerts`)

## Usage

```
NAME:
   scannerofcerts - Scan and reports on certificate in a IP range or hostlist

USAGE:
  scannerofcerts [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --targets value, -t value  host or list of host/ranges to be scanned. Multiple hosts may be separated by commas,
                              ranges can be specified with subnets (e.g. 10.10.10.0/24)
   --ports value, -p value    list of comma-separated ports to scan. - can be used to indicate ranges
                              (default: "21,22,25,110,119,143,389,433,443,465,563,585,636,853,981,989,990,992,993,994,
                                         995,1311,1443,1521,2083,2087,2096,2443,2484,3269,3443,4443,5061,5443,5986,
                                         6443,6679,6697,7002,7443,8443,8888,9443")
   --csv value                path to output for CSV file, disables stdout
   --stdout                   prints output to stdout, this implied if other output methods are not enabled 
                              (default: false)
   --timeout value            timeout (in ms) for the port scan (default: 20000)
   --parallelism value        parallelism level for the port scan (default: 2000)
   --help, -h                 show help (default: false)

```

## TODOs & Limitations

### TODOs

- Support targets range (- syntax, / syntax), list
- Certificate validation
- STARTTLS support
- Support non-privileged port scans
- Common certificate type heuristic (self-signed, Active Directory signed, Let's Encrypt signed, normal CA signed, ...)
- Support hostnames in addition to IPs/IP ranges
- Hostname inference via PTR DNS records
- Optional inferred data points (expired duration, ...)
- Sorting options (certificate thumbprint, date, ip, ...)
- Formalized testing
- Testing of build artifacts
- Docker container (offer docker container with libpcap)
- Mac support (on M1 & amd64)
- Arm support (on Linux)

### Limitations

- No pre-TLS support, e.g. SSLv2, SSLv3 (this is a Golang limitation, I believe)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[Apache 2.0](https://choosealicense.com/licenses/apache-2.0/)
