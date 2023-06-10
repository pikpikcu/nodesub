<h1 align="center">
  NODESUB
  <br>
</h1>

Nodesub is a command-line tool for finding subdomains in bug bounty programs. It supports various subdomain enumeration techniques and provides flexible options for customization.

# Features

<h1 align="left">
  <img src="https://raw.githubusercontent.com/pikpikcu/nodesub/main/nodesub.png" alt="nodesub" width="700px"></a>
  <br>
</h1>

- Perform subdomain enumeration using CIDR notation (Support input list).
- Perform subdomain enumeration using ASN (Support input list).
- Perform subdomain enumeration using a list of domains.

## Installation

To install Nodesub, use the following command:

`npm install -g nodesub`

**NOTE:**

- Edit File `~/.config/nodesub/config.ini`

# ✔️ Usage

```
nodesub -h
```

This will display help for the tool. Here are all the switches it supports.

```
Usage: nodesub [options]

Nodesub is a command-line tool for finding subdomains in bug bounty programs.

Options:
  -u, --url <domain>                     Main domain
  -l, --list <file>                      File with list of domains
  -c, --cidr <cidr/file>                 Perform subdomain enumeration using CIDR
  -a, --asn <asn/file>                   Perform subdomain enumeration using ASN
  -dns, --dnsenum                        Enable DNS Enumeration (if you enable this the enumeration process will be slow)
  -rl, --rate-limit <limit>              Rate limit for DNS requests (requests per second) (default: "0")
  -ip, --ips                             Ekstrak IPs in Subdomain Resolved
  -wl, --wildcard                        Filter subdomains by wildcard DNS resolution Default:(False)
  -r, --recursive                        Enable recursive subdomain enumeration
  -p, --permutations                     Enable subdomain permutations
  -re,--resolver <file>                  File with list of resolvers
  -w, --wordlist <file>                  Wordlist file
  -pr, --proxy <proxy>                   Proxy URL
  -pa, --proxy-auth <username:password>  Proxy authentication credentials
  -s, --size <size>                      Max old space size heap Default:(10048 MB)
  -d, --debug                            Show DNS resolution details
  -v, --verbose                          Enable verbose output
  -o, --output <file>                    Output file
  -f, --format <format>                  Output file format (txt, json, csv, pdf) (default: "txt")
  -h, --help                             display help for command
```

## ✔️ Examples

- Enumerate subdomains for a single domain:
  	```
	nodesub -u example.com
	```

- Enumerate subdomains for a list of domains from a file:
	```
	nodesub -l domains.txt
	```
- Perform subdomain enumeration using CIDR:

  ```
  node nodesub.js -c 192.168.0.0/24 -o subdomains.txt

  ```

  ```
  node nodesub.js -c CIDR.txt -o subdomains.txt

  ```
- Perform subdomain enumeration using ASN:
  ```
  node nodesub.js -a AS12345 -o subdomains.txt
  ```

  ```
  node nodesub.js -a ASN.txt -o subdomains.txt
  ```
- Enable recursive subdomain enumeration and output the results to a JSON file:
	```
	nodesub -u example.com -r -o output.json -f json
	```
## Output

The tool provides various output formats for the results, including:
- Text (txt)
- JSON (json)
- CSV (csv)
- PDF (pdf)

The output file contains the resolved subdomains, failed resolved subdomains, or all subdomains based on the options chosen.

### ✔️ ***Contribution

You can contribute in following ways:
  - Give suggestions to make it better
  - Fix issues & submit a pull request

## License

This project is licensed under the [MIT License](LICENSE).
