# Nodesub

Nodesub is a command-line tool for finding subdomains in bug bounty programs. It supports various subdomain enumeration techniques and provides flexible options for customization.

## Installation

To install Nodesub, use the following command:

`npm install -g nodesub`

**NOTE**
Edit File `~/.config/nodesub/config.ini`
## Usage

`nodesub [flags]`


### Options:

- `-u, --url <domain>`: Specify the main domain to enumerate subdomains.
- `-l, --list <file>`: Specify a file with a list of domains to enumerate subdomains.
- `-rl, --rate-limit <limit>`: Set the rate limit for DNS requests (requests per second). Default: 0 (no rate limit).
- `-wl, --wildcard`: Filter subdomains by wildcard DNS resolution. Default: false.
- `-w, --wordlist <file>`: Specify a wordlist file for subdomain permutation.
- `-r, --recursive`: Enable recursive subdomain enumeration.
- `-p, --permutations`: Enable subdomain permutations.
- `-re, --resolver <file>`: Specify a file with a list of DNS resolvers.
- `-pr, --proxy <proxy>`: Specify a proxy URL.
- `-pa, --proxy-auth <username:password>`: Specify proxy authentication credentials.
- `-s, --size <size>`: Set the max old space size heap. Default: 10048 MB.
- `-d, --debug`: Show DNS resolution details.
- `-v, --verbose`: Enable verbose output.
- `-o, --output <file>`: Specify an output file.
- `-f, --format <format>`: Specify the output file format (txt, json, csv, pdf). Default: txt.

## Examples

- Enumerate subdomains for a single domain:
  	`nodesub -u example.com`

- Enumerate subdomains for a list of domains from a file:
	`nodesub -l domains.txt`

- Enable recursive subdomain enumeration and output the results to a JSON file:
	`nodesub -u example.com -r -o output.json -f json`
