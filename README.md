# scannerofcerts

`scannerofcerts` is a Go utility to scan one or more ranges to detect SSL certificates.

Given an IP range, it will scan it for open SSL-associated ports, and report to a CSV file (or standard output) 
the results.

## Installation

`scannerofcerts` is a single binary distributed through the
[_Release_](https://github.com/marcolussetti/scannerofcerts/releases) section here on GitHub. No installation is
required and binaries are available for multiple platforms.

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
                              ranges can be specified with dashes (e.g. 10.0.0.0-10.0.0.254)
   --ports value, -l value    list of comma-separated ports to scan. - can be used to indicate ranges
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

### Limitations

- No pre-TLS support, e.g. SSLv2, SSLv3 (this is a Golang limitation, I believe)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/apache-2.0/)