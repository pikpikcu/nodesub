#!/usr/bin/env node

const dns = require('dns');
const fs = require('fs');
const axios = require('axios');
const cheerio = require('cheerio');
const fastGlob = require('fast-glob');
const Bottleneck = require('bottleneck');
const Spinner = require('cli-spinner').Spinner;
const figlet = require('figlet');
const cloudscraper = require('cloudscraper');
const subquest = require('subquest');
const net = require('net');
const forge = require('node-forge');
const https = require('https');
const DnsSocket = require('dns-socket');
const {
    promisify
} = require('util');
const FormData = require('form-data');
const resolve4 = promisify(dns.resolve4);
const os = require('os');
//const exec = util.promisify(require('child_process').exec);
const {
    v4: uuidv4
} = require('uuid');
const {
    exec
} = require('child_process');
const {
    createObjectCsvWriter
} = require('csv-writer');
const PDFDocument = require('pdfkit');
const {
    program
} = require('commander');
const clc = require('cli-color');
const URL = require('url').URL;
const path = require('path');
const rateLimit = require('axios-rate-limit');

// Proxy
const HttpProxyAgent = require('http-proxy-agent');
const HttpsProxyAgent = require('https-proxy-agent');
const SocksProxyAgent = require('socks-proxy-agent');

const version = '0.1.1';
const codename = 'pikpikcu';

program
    .description('Nodesub is a command-line tool for finding subdomains in bug bounty programs.')
    .option('-u, --url <domain>', 'Main domain')
    .option('-l, --list <file>', 'File with list of domains')
    .option('-c, --cidr <cidr/file>', 'Perform subdomain enumeration using CIDR')
    .option('-a, --asn <asn/file>', 'Perform subdomain enumeration using ASN')
    .option('-dns, --dnsenum', 'Enable DNS Enumeration (if you enable this the enumeration process will be slow)')
    .option('-rl, --rate-limit <limit>', 'Rate limit for DNS requests (requests per second)', '0')
    .option('-ip, --ips', 'Ekstrak IPs in Subdomain Resolved')
    .option('-wl, --wildcard', 'Filter subdomains by wildcard DNS resolution Default:(False)')
    .option('-r, --recursive', 'Enable recursive subdomain enumeration')
    .option('-p, --permutations', 'Enable subdomain permutations')
    .option('-re,--resolver <file>', 'File with list of resolvers')
    .option('-w, --wordlist <file>', 'Wordlist file')
    .option('-pr, --proxy <proxy>', 'Proxy URL')
    .option('-pa, --proxy-auth <username:password>', 'Proxy authentication credentials')
    .option('-s, --size <size>', 'Max old space size heap Default:(10048 MB)')
    .option('-d, --debug', 'Show DNS resolution details')
    .option('-v, --verbose', 'Enable verbose output')
    .option('-o, --output <file>', 'Output file')
    .option('-f, --format <format>', 'Output file format (txt, json, csv, pdf)', 'txt');

program.parse(process.argv);

const argv = program.opts();
const spinner = new Spinner();
spinner.setSpinnerString('|/-\\');

// Set max old space size for JavaScript heap
const defaultMaxOldSpaceSize = 10048; // Default heap size in MB

// Create an instance of axios with rate limiting
const axiosWithRateLimit = rateLimit(axios.create(), {
    maxRequests: 10, // Set the maximum number of requests per second
    perMilliseconds: 10000, // Set the time window in milliseconds
});

// Set Limit Shodan
let lastShodanCallTime = null;
let shodanCallCount = 0;
const shodanRateLimit = 2; // Limit on the number of summons per second
const shodanRateLimitInterval = 1000; // Time range in milliseconds (for example, 1000 ms = 1 second)

// Function to execute shell command and get the output
function runCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout) => {
            if (error) {
                reject(error);
            } else {
                resolve(stdout.trim());
            }
        });
    });
}

function isSubfinderInstalled() {
    try {
        runCommand('subfinder -h');
        return true;
    } catch (error) {
        return false;
    }
}

function isAmassInstalled() {
    try {
        runCommand('amass -h');
        return true;
    } catch (error) {
        return false;
    }
}

function isAlteryxInstalled() {
    try {
        runCommand('alterx --version');
        return true;
    } catch (error) {
        return false;
    }
}

function installAlteryx() {
    try {
        runCommand('go install github.com/projectdiscovery/alterx/cmd/alterx@latest');
        console.log(`${clc.green('[V]')} Alteryx installed successfully`);
    } catch (error) {
        console.error(`${clc.red('[!]')} Error installing Alteryx:`, error);
    }
}

// Function to set the delay (delay)
function delay(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

// Function to create directory
 
function createDirectory(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, {
            recursive: true
        });
    }
}

// Function to read wordlist file

function readWordlistFile(wordlistFile) {
    try {
        const data = fs.readFileSync(wordlistFile, 'utf8');
        const lines = data.split('\n').filter(Boolean); // Filter out empty lines
        return lines;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error reading wordlist file:`, error);
        return [];
    }
}

// Function to filter subdomains by wildcard DNS resolution
function filterWildcardSubdomains(subdomains) {
    if (argv.wildcard) {
        return subdomains;
    }

    return subdomains.filter(({
        isActive
    }) => isActive);
}

// Function to Extension Output file
function getOutputFileExtension(format) {
    if (format === 'txt') {
        return 'txt';
    } else if (format === 'json') {
        return 'json';
    } else if (format === 'csv') {
        return 'csv';
    } else if (format === 'pdf') {
        return 'pdf';
    } else {
        throw new Error('Invalid output file format');
    }
}

// Function to get the current user's home directory
async function getHomeDirectory() {
    let homeDirectory = '';
    if (process.platform === 'win32') {
        homeDirectory = await runCommand('echo %USERPROFILE%');
    } else {
        homeDirectory = await runCommand('echo $HOME');
    }
    return homeDirectory;
}

// Function to download file
async function downloadFile(url, filePath) {
    const response = await axios.get(url, {
        responseType: 'stream'
    });
    const writer = fs.createWriteStream(filePath);
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
    });
}

// createProxyAgent
function createProxyAgent(proxyUrl, proxyAuth) {
    const url = new URL(proxyUrl);
    let agent;

    if (url.protocol === 'http:' || url.protocol === 'https:') {
        agent = new HttpProxyAgent({
            protocol: url.protocol,
            host: url.hostname,
            port: url.port || (url.protocol === 'http:' ? 80 : 443),
            auth: proxyAuth,
        });
    } else if (url.protocol === 'socks4:' || url.protocol === 'socks5:') {
        agent = new SocksProxyAgent({
            protocol: url.protocol.replace(':', ''),
            host: url.hostname,
            port: url.port || 1080,
            auth: proxyAuth,
        });
    } else {
        throw new Error('Invalid proxy URL');
    }

    return agent;
}

// Function to execute HTTP request with proxy
async function executeRequest(domain) {
    try {
        const url = `https://${domain}`;
        const options = {};

        if (argv.proxy) {
            const proxyAuth = argv.proxyAuth || null;
            const proxyUrl = new URL(argv.proxy);
            const agentOptions = {
                protocol: proxyUrl.protocol,
                host: proxyUrl.hostname,
                port: proxyUrl.port || (proxyUrl.protocol === 'http:' ? 80 : 443),
                auth: proxyAuth,
            };

            if (proxyUrl.protocol === 'http:') {
                options.httpAgent = new HttpProxyAgent(agentOptions);
            } else if (proxyUrl.protocol === 'https:') {
                options.httpsAgent = new HttpsProxyAgent(agentOptions);
            } else if (proxyUrl.protocol === 'socks4:' || proxyUrl.protocol === 'socks5:') {
                options.httpAgent = new SocksProxyAgent(agentOptions);
                options.httpsAgent = new SocksProxyAgent(agentOptions);
            } else {
                throw new Error('Invalid proxy URL');
            }
        }

        const response = await axios.get(url, options);
        console.log(`Requests to domains: ${domain}`);
        // Proses respons
        if (argv.proxy) {
            const proxyHost = new URL(argv.proxy).hostname;
            const proxyPort = new URL(argv.proxy).port || (new URL(argv.proxy).protocol === 'http:' ? 80 : 443);
            const subdomain = domain.replace(`.${proxyHost}`, '');
            const proxyHistoryUrl = `http://${proxyHost}:${proxyPort}/subdomain/${subdomain}`;
            await axios.get(proxyHistoryUrl);
        }
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Failed execute HTTP request with proxy:`, error.response ? error.response.statusText : error.message);
    }
}

// Function to read API keys from config.ini file
function readApiKeys() {
    const configPath = path.join(process.env.HOME, '.config', 'nodesub', 'config.ini');
    const configData = fs.readFileSync(configPath, 'utf8');
    const lines = configData.split('\n').filter(Boolean);
    const apiKeys = {};

    for (const line of lines) {
        const [key, value] = line.split('=');
        apiKeys[key] = value.replace(/"/g, '').trim();
    }

    return apiKeys;
}

// Function to check if dnsrecon is installed
async function isDnsreconInstalled() {
    try {
        await runCommand('dnsrecon -h');
        return true;
    } catch (error) {
        return false;
    }
}

// Function to install dnsrecon
async function installDnsrecon() {
    try {
        console.log('Installing dnsrecon...');
        await runCommand('pip3 install dnsrecon');
        console.log('dnsrecon installed successfully.');
    } catch (error) {
        console.error('Error installing dnsrecon:', error);
    }
}

// Function to run dnsrecon and get the list of subdomains
async function runDnsrecon(domain) {
    try {
        const isInstalled = await isDnsreconInstalled();
        if (!isInstalled) {
            await installDnsrecon();
            if (!await isDnsreconInstalled()) {
                console.error('Failed to install dnsrecon. Please make sure dnsrecon is installed manually.');
                return [];
            }
        }

        const commands = [
		`dnsrecon -d ${domain} -t zonewalk 2>&1`,
		`dnsrecon -d ${domain} -k 2>&1`,
		`dnsrecon -d ${domain} -y -k -b --lifetime 10 --threads 15 -w 2>&1`,
	  ];

        const subdomains = [];

        for (const command of commands) {
            const output = await runCommand(command);
            const lines = output.split('\n');
            const extractedSubdomains = lines.map(line => {
                const match = line.match(/(^|\s)([a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}(\s|$)/g);
                if (match) {
                    return match[0].trim();
                }
            }).filter(Boolean);

            subdomains.push(...extractedSubdomains);
        }

        return subdomains;
    } catch (error) {
        console.error(clc.red('\n[!] Error running dnsrecon:'), error.response ? error.response.statusText : error.message);
        return [];
    }
}

// generateCombinations
function generateCombinations(chars, length) {
    const combinations = [];

    function generateCombination(currentCombination) {
        if (currentCombination.length === length) {
            combinations.push(currentCombination);
            return;
        }

        for (let i = 0; i < chars.length; i++) {
            const newCombination = currentCombination + chars[i];
            generateCombination(newCombination);
        }
    }

    generateCombination('');

    return combinations;
}

// DnsServers
async function getDnsServers() {
    const resolveFilePath = path.join(os.homedir(), '.config', 'nodesub', 'resolvers.txt');
    const resolvConf = await fs.promises.readFile(resolveFilePath, 'utf-8');
    const dnsServers = [];
    const lines = resolvConf.split('\n');

    for (const line of lines) {
        if (line.startsWith('nameserver')) {
            const parts = line.split(' ');
            const dnsServer = parts[1].trim();
            dnsServers.push(dnsServer);
        }
    }

    return dnsServers;
}

// subquest
async function getSubDomains(domain) {
    try {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789.-_';
        const dictionary = generateCombinations(chars, 3);
        fs.writeFileSync('dictionary.txt', dictionary.join('\n'));

        const dnsServers = await getDnsServers();
        const enumOptions = {
            host: domain,
            rateLimit: 500,
            port: Array.from({
                length: 65535
            }, (_, index) => (index + 1).toString()),
            dnsServer: dnsServers,
            recursive: false,
            dictionary: 'dictionary.txt',
        };

        const subdomains = await subquest.getSubDomains(enumOptions);
        return subdomains || [];
    } finally {
        fs.unlinkSync('dictionary.txt');
    }
}

// Subdomain enumeration with SecurityTrails
async function runSecurityTrails(domain, securityTrailsApiKey) {
    try {
        const curlCommand = `curl "https://api.securitytrails.com/v1/domain/${domain}/subdomains" -H 'apikey: ${securityTrailsApiKey}'`;
        const response = await runCommand(curlCommand);
        const data = JSON.parse(response);

        const subdomains = data.subdomains.map(subdomain => `${subdomain}.${domain}`);

        const uniqueSubdomains = Array.from(new Set(subdomains));
        uniqueSubdomains.sort();

        return uniqueSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running SecurityTrails:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}


// Anubis DB Subdomain Enumerations
async function runAnubisDB(domain) {
    try {
        const apiUrl = `https://jonlu.ca/anubis/subdomains/${domain}`;
        const response = await axiosWithRateLimit.get(apiUrl);
        const subdomains = response.data;
        subdomains.sort();

        return subdomains;
    } catch (error) {
        console.error(clc.red('\n[!] Error running anubis:'), error.response ? error.response.statusText : error.message);
        return [];
    }
}

// Function to run dnsenum and get the list of subdomains
async function runDnsenum(domain) {
    try {
      const commands = [
        `dnsenum ${domain} --enum --threads 5 -s 15 -w --zonewalk`,
        `dnsenum ${domain} --recursion --noreverse`,
        //`dnsenum ${domain} --dnsserver NS`,
      ];
  
      const outputs = await Promise.all(commands.map(command => runCommand(command)));
  
      const subdomains = outputs.flatMap(output => {
        const lines = output.split('\n');
        return lines.map(line => {
          const match = line.match(/^(\*\.)?([a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/g);
          if (match) {
            return match[0];
          }
        }).filter(Boolean);
      });
  
      return subdomains;
    } catch (error) {
      console.error(clc.red('\n[!] Error running dnsenum:'), error.response ? error.response.statusText : error.message);
      return [];
    }
}

// runBaiduSearch
async function runBaiduSearch(domain, page = 1) {
    try {
        const url = new URL(`https://www.baidu.com/s?wd=site%3A*.${domain}&pn=${(page - 1) * 10}`);
        //const response = await axios.get(url.href);
        const response = await axiosWithRateLimit.get(url.href);
        const $ = cheerio.load(response.data);
        const subdomains = new Set();

        // Get all search results
        $('.c-container').each((index, element) => {
            const mu = $(element).attr('mu=');
            if (mu) {
                const subdomainMatches = mu.match(/\/\/([^/]+)\./);
                if (subdomainMatches && subdomainMatches.length > 1) {
                    const subdomain = subdomainMatches[1];
                    subdomains.add(subdomain);
                }
            }
        });

        // Sort subdomains
        const sortedSubdomains = Array.from(subdomains).sort();

        return sortedSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running Baidu search:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}


// Function to run Bing search and get the list of subdomains
async function runBing(domain, first) {
    try {
        const url = `https://www.bing.com/search?q=${domain}+-www&sp=-1&ghc=1&lq=0&pq=${domain}+-www&sc=0-25&qs=n&sk=&cvid=10BD11349D554525AB05E3626258B00E&ghsh=0&ghacc=0&ghpl=&FPIG=955CADBBFF1D4009AF95D073654A5BFA%2c9CE86F91D3BE436C983233A8216C0F50&first=${first}&FORM=PERE1`;
        //const response = await axios.get(url);
        const response = await axiosWithRateLimit.get(url);
        const $ = cheerio.load(response.data);
        const subdomains = [];

        const subdomainRegex = /(?:https?:\/\/)?(([^/]+))\//;

        $('.b_algo').each((index, element) => {
            const link = $(element).find('a').attr('href');
            const subdomainMatch = link.match(subdomainRegex);
            if (subdomainMatch && subdomainMatch[0].includes(domain)) {
                const subdomain = subdomainMatch[1];
                subdomains.push(subdomain);
            }
        });

        // Remove duplicates and sort subdomains
        const uniqueSubdomains = Array.from(new Set(subdomains));
        uniqueSubdomains.sort();

        // Check if there are more pages and fetch them recursively
        const nextLink = $('.sb_pagN').find('a').attr('href');
        if (nextLink) {
            const nextPage = nextLink.split('&first=')[1];
            const nextPageSubdomains = await runBing(domain, nextPage);
            uniqueSubdomains.push(...nextPageSubdomains);
        }

        return uniqueSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running Bing search:`, error.response ? error.response.statusText : error.message);
    }
}

// Function to run crt.sh and fetch subdomains
async function runCrtsh(domain) {
    try {
        const urls = [
			`https://crt.sh/?q=%.${domain}`,
			`https://crt.sh/?q=%.%.${domain}`,
			`https://crt.sh/?q=%.%.%.${domain}`,
			`https://crt.sh/?q=%.%.%.%.${domain}`,
			`https://crt.sh/?q=%.%.%.%.%.${domain}`,
			`https://crt.sh/?q=%.%.%.%.%.%.${domain}`,
		];

        const subdomains = [];

        for (const url of urls) {
            const response = await axiosWithRateLimit.get(url, {
                maxRedirects: 0,
                timeout: 70000 // Set the timeout value according to your needs
            });
            const $ = cheerio.load(response.data);

            // Get all subdomains
            $('table tr').each((index, element) => {
                const subdomainText = $(element).find('td:nth-child(5)').text().trim();
                const subdomainMatches = subdomainText.match(/([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z\.]{2,})/);
                if (subdomainMatches && subdomainMatches.length > 0) {
                    const subdomain = subdomainMatches[0];
                    if (subdomain.endsWith(domain)) { // ensure the subdomain belongs to the main domain
                        subdomains.push(subdomain);
                    }
                }
            });
        }

        // Sort and remove duplicates from subdomains
        const uniqueSubdomains = Array.from(new Set(subdomains));
        uniqueSubdomains.sort();

        return uniqueSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running crt.sh:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}

// Function to fetch subdomains from AlienVault OTX API
async function fetchAlienVaultSubdomains(domain) {
    try {
        const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
        const response = await axios.get(url);
        const {
            data
        } = response;

        // Extract subdomains from the response
        const subdomains = data.passive_dns.map((record) => record.hostname);

        // Sort and remove duplicates from subdomains
        const uniqueSubdomains = Array.from(new Set(subdomains));
        uniqueSubdomains.sort();

        return uniqueSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error fetching subdomains from AlienVault OTX:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}

// Subdomain enumeration with Shodan
async function runShodan(domain, shodanApiKey) {
    try {
        // Rate limit Shodan requests
        if (lastShodanCallTime) {
            const elapsedTime = Date.now() - lastShodanCallTime;
            if (elapsedTime < shodanRateLimitInterval) {
                await delay(shodanRateLimitInterval - elapsedTime);
            }
        }

        const url = `https://api.shodan.io/dns/domain/${domain}?key=${shodanApiKey}`;
        const response = await axios.get(url);
        const data = response.data;

        lastShodanCallTime = Date.now();
        shodanCallCount++;

        const subdomains = data.subdomains.map(subdomain => `${subdomain}."${domain}"`);

        // Sort and remove duplicates from subdomains
        const uniqueSubdomains = Array.from(new Set(subdomains));
        uniqueSubdomains.sort();

        return uniqueSubdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running Shodan:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}

// Function to run Amass and get the list of subdomains
async function runAmass(domain) {
    try {
        const isInstalled = isAmassInstalled();
        if (!isInstalled) {
            console.log(`${clc.red('\n[!]')} Amass is not installed. Installing Amass...`);
            await runCommand('go install -v github.com/owasp-amass/amass/v3/...@master');
        }
        const commands = [
            `amass enum -d "${domain}" -passive`,
            //`amass enum -d "${domain}" -active`,
        ];
        const output = await Promise.all(commands.map(runCommand));
        const subdomains = output.join('\n').split('\n');
        return subdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running Amass:`, error);
        return [];
    }
}

// Function to run Subfinder and get the list of subdomains
async function runSubfinder(domain) {
    try {
        const isInstalled = isSubfinderInstalled();
        if (!isInstalled) {
            console.log(`${clc.red('\n[!]')} Subfinder is not installed. Installing Subfinder...`);
            await runCommand('go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest');
        }

        const commands = [
            `subfinder -all -d "${domain}" -rl 100 -recursive`,
            `subfinder -all -d "${domain}" -rl 1000 -active`,
            //`echo "${domain}" | subfinder -silent -all -recursive | subfinder -rl 1000 `,
        ];

        const output = await Promise.all(commands.map(runCommand));
        const subdomains = output.join('\n').split('\n');
        return subdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running Subfinder:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}


// Function to perform subdomain permutations using AlterX
async function generatePermutations(domain) {
    try {
        const subdomains = [];

        if (!isAlteryxInstalled()) {
            console.log(`${clc.red('\n[!]')} Alteryx is not installed. Installing Alteryx...`);
            installAlteryx();
        }
        const commands = [
		`echo "${domain}" | alterx`,
		`echo "${domain}" | alterx -enrich -p '{{word}}.{{suffix}}'`,
		`echo "${domain}" | alterx -enrich -p '{{word}}-{{year}}.{{suffix}}'`,
		`echo "${domain}" | alterx -enrich`,
		`echo "${domain}" | alterx -enrich -p '{{number}}.{{suffix}}'`,
		`echo "${domain}" | alterx -enrich -p '{{number}}-{{word}}.{{suffix}}'`
	  ];

        const output = await Promise.all(commands.map(runCommand));
        output.forEach(result => {
            subdomains.push(...result.trim().split('\n'));
        });

        return subdomains;
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error running AlterX:`, error.response ? error.response.statusText : error.message);
        return [];
    }
}


// Function to execute DNS query and get the IP address
async function resolveDomain(subdomain) {
    try {
        if (!argv.resolver) {
            // If argv.resolver is not provided, directly pass empty resolver
            const addresses = await dns.promises.resolve(subdomain, 'A');
            if (addresses && addresses.length > 0) {
                if (argv.debug) {
                    console.log(`${clc.green('[V]')} Resolved subdomain ${subdomain}:`, addresses);
                }
                return subdomain; // Return the original subdomain
            }
        } else {
            // Load custom resolvers from file
            const resolvers = fs.readFileSync(argv.resolver, 'utf8').split('\n').filter(Boolean);

            const addresses = await dns.promises.resolve(subdomain, 'A', {
                resolver: resolvers, // Use custom resolvers
            });

            if (addresses && addresses.length > 0) {
                if (argv.debug) {
                    console.log(`${clc.green('[V]')} Resolved subdomain ${subdomain}:`, addresses);
                }
                return subdomain; // Return the original subdomain
            }
        }
    } catch (error) {
        if (argv.verbose && argv.debug) {
            console.error(`${clc.red('\n[!]')} Error resolving subdomain ${subdomain}:`, error.response ? error.response.statusText : error.message);
        }
    }

    return null; // Mark resolution as failed
}

// Function to perform subdomain enumeration
async function enumerateSubdomains(domain, subdomains) {
    const resolvedSubdomains = [];
    const failedSubdomains = [];

    // Loop through each subdomain and resolve them in parallel
    const resolvedPromises = subdomains.map(async (subdomain) => {
        try {
            let isActive;
            if (argv.rateLimit > 0) {
                const [result] = await rateLimitDNSRequests([subdomain]);
                isActive = result.isActive;
            } else {
                isActive = await resolveDomain(subdomain);
            }

            if (isActive) {
                resolvedSubdomains.push({
                    subdomain,
                    isActive
                });
            } else {
                failedSubdomains.push({
                    subdomain,
                    isActive
                });
            }
        } catch (error) {
            console.error(`${clc.red('\n[!]')} Error resolving subdomain ${subdomain}:`, error.response ? error.response.statusText : error.message);
            failedSubdomains.push({
                subdomain,
                isActive: false
            });
        }
    });

    await Promise.all(resolvedPromises);

    return {
        resolvedSubdomains,
        failedSubdomains
    }; // Return both resolved and subdomains
}

// Function to rate limit DNS requests
async function rateLimitDNSRequests(subdomains) {
    const rateLimit = parseInt(argv.rateLimit);
    if (rateLimit <= 0) {
        return subdomains;
    }

    const limiter = new Bottleneck({
        maxConcurrent: rateLimit,
        minTime: 10000 / rateLimit,
    });

    const rateLimitedSubdomains = subdomains.map((subdomain) => {
        return limiter.schedule(async () => {
            try {
                let isActive;
                if (argv.rateLimit > 0) {
                    const [result] = await rateLimitDNSRequests([subdomain]);
                    isActive = result.isActive;
                } else {
                    isActive = await resolveDomain(subdomain);
                }

                return {
                    subdomain,
                    isActive
                };
            } catch (error) {
                console.error(`${clc.red('\n[!]')} Error resolving domain ${subdomain}:`, error.response ? error.response.statusText : error.message);
                return {
                    subdomain,
                    isActive: false
                };
            }
        });
    });

    await Promise.all(rateLimitedSubdomains); // Await the resolution of DNS requests

    return rateLimitedSubdomains;
}

// Function to perform recursive subdomain enumeration
async function performRecursiveEnumeration(domain, wordlist) {
    const discoveredSubdomains = [];
    const resolvedSubdomains = [];
    const failedSubdomains = [];

    // Function to recursively enumerate subdomains
    async function enumerateSubdomainsRecursive(subdomain, wordlist) {
        const fullSubdomain = `${subdomain}.${domain}`;
        const isActive = await resolveDomain(fullSubdomain);

        if (isActive) {
            resolvedSubdomains.push({
                subdomain: fullSubdomain,
                isActive
            });
            discoveredSubdomains.push(fullSubdomain);
        } else {
            failedSubdomains.push({
                subdomain: fullSubdomain,
                isActive
            });
        }

        // Recursive call to enumerate subdomains
        for (const word of wordlist) {
            const newSubdomain = `${word}.${subdomain}`;
            await enumerateSubdomainsRecursive(newSubdomain, wordlist);
        }
    }

    // Start the recursive enumeration
    for (const word of wordlist) {
        const subdomain = `${word}.${domain}`;
        await enumerateSubdomainsRecursive(subdomain, wordlist);
    }

    return {
        discoveredSubdomains,
        resolvedSubdomains,
        failedSubdomains
    };
}

// Function to perform subdomain brute force using wordlist with early exit
async function bruteForceSubdomains(domain, wordlist) {
    const CHUNK_SIZE = 10000; // Set the chunk size for wordlist processing
    const subdomains = [];
    const accuracy = 0.5; // Desired accuracy (50%)

    // Chunk the wordlist into smaller arrays
    const chunks = [];
    for (let i = 0; i < wordlist.length; i += CHUNK_SIZE) {
        chunks.push(wordlist.slice(i, i + CHUNK_SIZE));
    }

    // Loop through each chunk of the wordlist
    for (const chunk of chunks) {
        // Loop through each word in the chunk
        for (const word of chunk) {
            const subdomain = `${word}.${domain}`;

            // Perform early exit check
            if (await earlyExitCheck(subdomain, accuracy)) {
                subdomains.push(subdomain);
            }
        }
    }

    return subdomains;
}

// Function to perform early exit check for subdomain
async function earlyExitCheck(subdomain, accuracy) {
    const maxAttempts = Math.ceil(subdomain.length * (1 - accuracy));

    // Loop through each character of the subdomain
    for (let i = 0; i < subdomain.length; i++) {
        const prefix = subdomain.slice(0, i + 1);
        const isActive = await resolveDomain(prefix);

        // If the prefix does not resolve, return false
        if (!isActive) {
            return true;
        }

        // If the maximum number of attempts is reached, return true
        if (i + 100 >= maxAttempts) {
            return true;
        }
    }

    // If all characters are resolved, return true
    return true;
}

// Function to get subdomains from CIDR
async function getSubdomainsFromCIDR(cidr) {
    try {
      const subdomains = [];
      // Perform subdomain enumeration using CIDR
      // Replace the following code with your own implementation to extract subdomains from CIDR
      // Example implementation using 'amass', 'mapcidr' command line tool
      const commands = [
        `amass intel -cidr ${cidr}`,
        `echo ${cidr} | mapcidr -silent | tlsx -cn -silent -nc | tr -d '[]' | awk '{print $2}'`,
      ];
      const output = await Promise.all(commands.map(runCommand));
      output.forEach((cmdOutput) => {
        const lines = cmdOutput.split('\n');
        lines.forEach((line) => {
          const matches = line.match(/\b([a-zA-Z0-9.-]+)\b/g);
          if (matches) {
            subdomains.push(...matches);
          }
        });
      });
  
      return subdomains;
    } catch (error) {
      console.error(`${clc.red('\n[!]')} Error getting subdomains from CIDR:`, error.response ? error.response.statusText : error.message);
      return [];
    }
}

// Function to get subdomains from ASN using whois
async function getSubdomainsFromASN(asn) {
    try {
      const subdomains = [];
      // Perform subdomain enumeration using ASN
      // Replace the following code with your own implementation to extract subdomains from ASN
      // Example implementation using 'amass', 'asnmap', and 'whois' command line tools
      const commands = [
        `amass intel -asn ${asn}`,
        `asnmap -a ${asn} -silent | mapcidr -silent | tlsx -cn -silent -nc | tr -d '[]' | awk '{print $2}'`,
        `whois -h whois.radb.net -- '-i origin ${asn}' | grep -Eo "([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}"`,
      ];
      const output = await Promise.all(commands.map(runCommand));
      output.forEach((cmdOutput) => {
        const lines = cmdOutput.split('\n');
        lines.forEach((line) => {
          const matches = line.match(/\b([a-zA-Z0-9.-]+)\b/g);
          if (matches) {
            subdomains.push(...matches);
          }
        });
      });
      return subdomains;
    } catch (error) {
      console.error(`${clc.red('\n[!]')} Error getting subdomains from ASN:`, error.response ? error.response.statusText : error.message);
      return [];
    }
}

// Function to get subdomains using DNS Dumpster Diving technique
//async function getSubdomainsFromDnsDumpster(domain) {
//    const socket = new DnsSocket();
//    const subdomains = [];
//    const dnsTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV'];
//  
//    await Promise.all(
//      dnsTypes.map((type) => {
//        return new Promise((resolve, reject) => {
//          socket.query({ questions: [{ type, name: `${domain}` }] }, 53, '8.8.8.8', (err, res) => {
//            if (err) {
//              reject(err);
//              return;
//            }
//  
//            const answers = res.answers.filter(answer => answer.type === 'A');
//  
//            answers.forEach(answer => {
//              const subdomain = answer.name.replace(`.${domain}`, '');
//              subdomains.push(subdomain);
//            });
//  
//            resolve(); // Resolve after all answers are processed
//          });
//  
//          // Timeout for each DNS query
//          setTimeout(() => {
//            reject(new Error(`DNS query for type ${type} timed out`));
//          }, 5000); // Adjust the timeout duration as needed
//        });
//      })
//    );
//  
//    return subdomains;
//}

// Subdomains from DNS Cache Snooping
async function getSubdomainsFromDNSCache(domain) {
    try {
      const subdomains = [];
  
      // Resolve the domain to get the IP addresses of the authoritative nameservers
      const { address: authoritativeServer } = await dns.promises.resolve4(domain);
  
      // Query the DNS cache server for all subdomains
      const dnsCacheServer = authoritativeServer;
      const { answer } = await dns.promises.resolveAny(`${domain}.`, { server: { address: dnsCacheServer } });
  
      if (!answer) {
        return subdomains; // No answer received, return empty array
      }
  
      // Extract the subdomains from the DNS cache response
      answer.forEach((record) => {
        if (record.type === 'CNAME') {
          subdomains.push(record.value.replace(`.${domain}.`, ''));
        }
      });
  
      return subdomains;
    } catch (error) {
      throw error;
    }
}

// Ripe Data
async function getSubdomainsFromRipeData(domain) {
    try {
      const url = `https://stat.ripe.net/data/dns-chain/data.json?resource=${domain}`;
      const response = await axios.get(url);
      const data = response.data;
  
      if (data && data.data && data.data.forward_nodes) {
        const subdomains = Object.keys(data.data.forward_nodes);
        return subdomains;
      } else {
        return [];
      }
    } catch (error) {
      throw error;
    }
  }

// Function to get subdomains from SSL/TLS certificates
async function getSubdomainsFromCertificateInfo(certificate) {
    const subdomains = [];
  
    // Extract subdomains from the certificate information
    const { extensions } = certificate;
    if (extensions) {
      extensions.forEach((extension) => {
        if (extension.name === 'subjectAltName') {
          const altNames = extension.altNames;
          altNames.forEach((altName) => {
            if (altName.type === 2) { // DNS type
              subdomains.push(altName.value);
            }
          });
        }
      });
    }
  
    return subdomains;
}
  
// Function to get subdomains from SSL/TLS certificates
async function getSubdomainsFromCertificate(domain) {
    return new Promise((resolve, reject) => {
      const options = {
        host: domain,
        port: 443,
        method: 'GET',
        rejectUnauthorized: false
      };
  
      const req = https.request(options, (res) => {
        const certificate = res.socket.getPeerCertificate();
        const subdomains = getSubdomainsFromCertificateInfo(certificate);
        resolve(subdomains);
      });
  
      req.on('error', (error) => {
        reject(error.response ? error.response.statusText : error.message);
      });
  
      req.end();
    });
}

// Resolve and save subdomains for a single domain
async function resolveAndSaveSubdomains(domain, outputFile, subdomains) {
    spinner.setSpinnerTitle(`${clc.green('[V]')} Processing Subdomains Resolving... %s`);
    spinner.start();

    let resolvedSubdomains = [];
    let failedSubdomains = [];
    let allSubdomains = [];

    try {
        const rateLimitedSubdomains = await rateLimitDNSRequests(subdomains); // Rate limit DNS requests
        const result = await enumerateSubdomains(domain, subdomains, rateLimitedSubdomains); // Resolve subdomains
        resolvedSubdomains = result.resolvedSubdomains;
        failedSubdomains = result.failedSubdomains;
        spinner.stop(true);
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error Resolving Subdomains:`, error.response ? error.response.statusText : error.message);
    }

    spinner.stop(true);

    // Print the number of subdomains found
    console.log(`${clc.green('[*]')} Resolved Subdomains: ${clc.yellowBright(Array.from(new Set(resolvedSubdomains)).length)}`);
    console.log(`${clc.red('[!]')} Failed Resolved Subdomains: ${clc.yellowBright(Array.from(new Set(failedSubdomains)).length)}`);

    // Print subdomains if verbose flag is enabled
    if (argv.verbose) {
        console.log(`${clc.green('[*]')} Resolved Subdomains:`);
        const uniqueResolvedSubdomains = [...new Set(resolvedSubdomains.map(({
            subdomain
        }) => subdomain))];
        console.log(uniqueResolvedSubdomains);

        console.log(`${clc.red('[!]')} Failed Resolved Subdomains:`);
        const uniqueFailedSubdomains = [...new Set(failedSubdomains.map(({
            subdomain
        }) => subdomain))];
        console.log(uniqueFailedSubdomains);
    }

    // Remove duplicates and sort subdomains
    const uniqueResolvedSubdomains = Array.from(new Set(resolvedSubdomains.map(({
        subdomain
    }) => subdomain)));
    const uniqueFailedSubdomains = Array.from(new Set(failedSubdomains.map(({
        subdomain
    }) => subdomain)));
    const uniqueAllSubdomains = Array.from(new Set([...uniqueResolvedSubdomains, ...uniqueFailedSubdomains]));

    uniqueResolvedSubdomains.sort();
    uniqueFailedSubdomains.sort();
    uniqueAllSubdomains.sort();

    // Remove quotes from subdomains
    const cleanedResolvedSubdomains = uniqueResolvedSubdomains.map(subdomain => subdomain.replace(/"/g, ''));
    const cleanedFailedSubdomains = uniqueFailedSubdomains.map(subdomain => subdomain.replace(/"/g, ''));
    const cleanedAllSubdomains = uniqueAllSubdomains.map(subdomain => subdomain.replace(/"/g, ''));

    // Save the results to an output file if provided
    if (outputFile) {
        let resolvedOutputFile;
        let failedOutputFile;
        let allOutputFile;
        let ipOutputFile;

            // Generate output file names based on the input options
        if (argv.cidr) {
            resolvedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_resolved_cidr.${getOutputFileExtension(argv.format)}`;
            failedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_noresolved_cidr.${getOutputFileExtension(argv.format)}`;
            allOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_all_cidr.${getOutputFileExtension(argv.format)}`;
            ipOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_ips_cidr.${getOutputFileExtension(argv.format)}`; 
        } else if (argv.asn) {
            resolvedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_resolved_asn.${getOutputFileExtension(argv.format)}`;
            failedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_noresolved_asn.${getOutputFileExtension(argv.format)}`;
            allOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_all_asn.${getOutputFileExtension(argv.format)}`;
            ipOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_ips_asn.${getOutputFileExtension(argv.format)}`; 
        } else {
            resolvedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_resolved_${domain}.${getOutputFileExtension(argv.format)}`;
            failedOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_noresolved_${domain}.${getOutputFileExtension(argv.format)}`;
            allOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_all_${domain}.${getOutputFileExtension(argv.format)}`;
            ipOutputFile = `${outputFile.replace(/\.([^.]+)$/, '')}_ips_${domain}.${getOutputFileExtension(argv.format)}`; 
        }
        
        const resolvedOutputData = cleanedResolvedSubdomains.join('\n');
        const failedOutputData = cleanedFailedSubdomains.join('\n');
        const allOutputData = cleanedAllSubdomains.join('\n');
        const ipOutputData = []; 

        // Extract IPs for resolved subdomains
        if (argv.ips) {
            for (const subdomain of uniqueResolvedSubdomains) {
                try {
                    const ipAddresses = await resolve4(subdomain);
                    ipOutputData.push(`${subdomain}: ${ipAddresses.join(', ')}`);
                } catch (error) {
                    // Ignore DNS resolution errors and continue
                }
            }

            // Save IP output to a file
            if (ipOutputData.length > 0) {
                fs.writeFileSync(ipOutputFile, ipOutputData.join('\n'), 'utf8');
                console.log(`${clc.green('[v]')} IP addresses for resolved subdomains saved to: ${clc.yellowBright(ipOutputFile)}`);
            }
        }

        if (argv.format === 'txt') {
            fs.writeFileSync(resolvedOutputFile, resolvedOutputData, 'utf8');
            fs.writeFileSync(failedOutputFile, failedOutputData, 'utf8');
            fs.writeFileSync(allOutputFile, allOutputData, 'utf8');
            console.log(`${clc.green('[v]')} Resolved Subdomains saved to: ${clc.yellowBright(resolvedOutputFile)}`);
            console.log(`${clc.red('[!]')} Failed Resolved Subdomains saved to: ${clc.yellowBright(failedOutputFile)}`);
            console.log(`${clc.green('[*]')} All Subdomains saved to: ${clc.yellowBright(allOutputFile)}`);
        } else if (argv.format === 'json') {
            const resolvedJsonData = JSON.stringify(cleanedResolvedSubdomains, null, 2);
            const failedJsonData = JSON.stringify(cleanedFailedSubdomains, null, 2);
            const allJsonData = JSON.stringify(cleanedAllSubdomains, null, 2);
            fs.writeFileSync(resolvedOutputFile, resolvedJsonData, 'utf8');
            fs.writeFileSync(failedOutputFile, failedJsonData, 'utf8');
            fs.writeFileSync(allOutputFile, allJsonData, 'utf8');
            console.log(`${clc.green('[v]')} Resolved Subdomains saved to: ${clc.yellowBright(resolvedOutputFile)}`);
            console.log(`${clc.red('[!]')} Failed Resolved Subdomains saved to: ${clc.yellowBright(failedOutputFile)}`);
            console.log(`${clc.green('[*]')} All Subdomains saved to: ${clc.yellowBright(allOutputFile)}`);
        } else if (argv.format === 'csv') {
            const resolvedCsvWriter = createObjectCsvWriter({
                path: resolvedOutputFile,
                header: [{
                    id: 'subdomain',
                    title: 'Subdomain'
		  }],
            });
            const failedCsvWriter = createObjectCsvWriter({
                path: failedOutputFile,
                header: [{
                    id: 'subdomain',
                    title: 'Subdomain'
		  }],
            });
            const allCsvWriter = createObjectCsvWriter({
                path: allOutputFile,
                header: [{
                    id: 'subdomain',
                    title: 'Subdomain'
		  }],
            });
            await resolvedCsvWriter.writeRecords(cleanedResolvedSubdomains.map((subdomain) => ({
                subdomain
            })));
            await failedCsvWriter.writeRecords(cleanedFailedSubdomains.map((subdomain) => ({
                subdomain
            })));
            await allCsvWriter.writeRecords(cleanedAllSubdomains.map((subdomain) => ({
                subdomain
            })));
            console.log(`${clc.green('[v]')} Resolved Subdomains saved to: ${clc.yellowBright(resolvedOutputFile)}`);
            console.log(`${clc.red('[!]')} Failed Resolved Subdomains saved to: ${clc.yellowBright(failedOutputFile)}`);
            console.log(`${clc.green('[*]')} All Subdomains saved to: ${clc.yellowBright(allOutputFile)}`);
        } else if (argv.format === 'pdf') {
            const PDFDocument = require('pdfkit');
            const resolvedPdf = new PDFDocument();
            const failedPdf = new PDFDocument();
            const allPdf = new PDFDocument();

            resolvedPdf.pipe(fs.createWriteStream(resolvedOutputFile));
            failedPdf.pipe(fs.createWriteStream(failedOutputFile));
            allPdf.pipe(fs.createWriteStream(allOutputFile));

            resolvedPdf.font('Helvetica-Bold').text('Resolved Subdomains', {
                fontSize: 24,
                align: 'center'
            });
            resolvedPdf.moveDown();
            resolvedPdf.font('Helvetica').fontSize(12).text(uniqueResolvedSubdomains.join('\n'), {
                align: 'left'
            });
            resolvedPdf.end();

            failedPdf.font('Helvetica-Bold').text('Failed Resolved Subdomains', {
                fontSize: 24,
                align: 'center'
            });
            failedPdf.moveDown();
            failedPdf.font('Helvetica').fontSize(12).text(uniqueFailedSubdomains.join('\n'), {
                align: 'left'
            });
            failedPdf.end();

            allPdf.font('Helvetica-Bold').text('All Subdomains', {
                fontSize: 24,
                align: 'center'
            });
            allPdf.moveDown();
            allPdf.font('Helvetica').fontSize(12).text(uniqueAllSubdomains.join('\n'), {
                align: 'left'
            });
            allPdf.end();
            console.log(`${clc.green('[v]')} Resolved Subdomains saved to: ${clc.yellowBright(resolvedOutputFile)}`);
            console.log(`${clc.red('[!]')} Failed Resolved Subdomains saved to: ${clc.yellowBright(failedOutputFile)}`);
            console.log(`${clc.green('[*]')} All Subdomains saved to: ${clc.yellowBright(allOutputFile)}`);
        } else {
            console.error(`${clc.red('[!]')} Invalid output file format`);
        }
    }

    return;
}

// Main
async function main() {
    try {
        const homeDirectory = await getHomeDirectory();
        const configDirectory = path.join(homeDirectory, '.config', 'nodesub');

        // Parse command-line arguments
        const {
            url,
            list,
            output,
            recursive,
            wordlist,
            size
        } = argv;

        if (!fs.existsSync(configDirectory)) {
            fs.mkdirSync(configDirectory, {
                recursive: true
            });

            // Create a config.ini file with shodan="API_KEY"
            const configPath = path.join(configDirectory, 'config.ini');
            const shodanApiKey = 'API_KEY';
            const securityTrailsApiKey = 'API_KEY';
            const configContent = [
				`shodan="${shodanApiKey}"`,
				`securitytrails="${securityTrailsApiKey}"`
			];
            fs.writeFileSync(configPath, configContent.join('\n'));

            // Download default_wordlists and save them in ~/.config/nodesub folder
            const wordlistUrls = [
				'https://gist.githubusercontent.com/pikpikcu/679a73409a9b241aca11e7957cbb1630/raw/f87b5161d318bf1ff825cc57bd9102f9b99fc932/default_wordlist.txt',
				'https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt',
			];
            const wordlistPaths = [
				path.join(configDirectory, 'default_wordlist.txt'),
				path.join(configDirectory, 'resolvers.txt')
			];

            await Promise.all(wordlistUrls.map(async (url, index) => {
                await downloadFile(url, wordlistPaths[index]);
            }));
        }

        const outputDirectory = path.dirname(output || '');
        // Check if the output directory exists, create it if not
        if (output) {
            const outputDirectory = path.dirname(output || '');
            if (!fs.existsSync(outputDirectory)) {
                fs.mkdirSync(outputDirectory, {
                    recursive: true
                });
            }
        }

        console.log(clc.greenBright(figlet.textSync('NodeSub', 'Poison')));
        console.log(clc.yellowBright(`\t\t\t [🛠]Version:`, clc.whiteBright(`${version}`)));
        console.log(clc.blueBright(`\t\t\t{🖥}codename:`, clc.redBright(`${codename}\n\n\n\n`)));

        // Function to read subdomains from a file
        function readSubdomainsFromFile(filePath) {
            try {
            const subdomains = fs.readFileSync(filePath, 'utf8').split('\n');
            return subdomains;
            } catch (error) {
            console.error(`${clc.red('\n[!]')} Error reading subdomains from file:`, error);
            return [];
            }
        }

        if (argv.cidr) {
            const cidr = argv.cidr;
            const outputFile = argv.output;
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Start Processing Subdomain Enumerations from CIDR: ${clc.yellow(`[${cidr}]`)} %s`);
            spinner.start();
          
            let subdomains = [];
            if (fs.existsSync(cidr)) {
              // Read CIDR from file if the input is a file path
              cidrfile = readSubdomainsFromFile(cidr);
              subdomains = await getSubdomainsFromCIDR(cidrfile);
            } else {
              // Otherwise, assume the input is a CIDR
              subdomains = await getSubdomainsFromCIDR(cidr);
            }
          
            spinner.stop(true);
            await resolveAndSaveSubdomains(cidr, outputFile, subdomains);
            return;
          }
          
        if (argv.asn) {
            const asn = argv.asn;
            const outputFile = argv.output;
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Start Processing Subdomain Enumerations from ASN: ${clc.yellow(`[${asn}]`)} %s`);
            spinner.start();
          
            let subdomains = [];
            if (fs.existsSync(asn)) {
              // Read ASN from file if the input is a file path
              asnfile = readSubdomainsFromFile(asn);
              subdomains = await getSubdomainsFromCIDR(asnfile);
            } else {
              // Otherwise, assume the input is an ASN
              subdomains = await getSubdomainsFromASN(asn);
            }
          
            spinner.stop(true);
            await resolveAndSaveSubdomains(asn, outputFile, subdomains);
            return;
        }

        if (!url && !list) {
            console.error(`${clc.red('[!]')} Please provide the URL or list option`);
            return;
        }

        if (url && list) {
            console.error(`${clc.yellow('[*]')} Please provide either the URL or list option, not both`);
            return;
        }

        if (argv.url) {
            const outputFile = argv.output;
            await processSubdomainEnumerations(url, outputFile, recursive, wordlist);
        }

        if (size) {
            const maxOldSpaceSize = parseInt(argv.size);
            if (maxOldSpaceSize > 0) {
                process.env.NODE_OPTIONS = `--max-old-space-size=${maxOldSpaceSize}`;
            } else {
                process.env.NODE_OPTIONS = `--max-old-space-size=${defaultMaxOldSpaceSize}`;
            }
        } else {
            process.env.NODE_OPTIONS = `--max-old-space-size=${defaultMaxOldSpaceSize}`;
        }

        if (argv.list) {
            // Read the list of URLs from the file
            try {
                const data = fs.readFileSync(argv.list, 'utf8');
                lines = data.split('\n').filter(Boolean);
            } catch (error) {
                console.error(`${clc.red('[!]')} Error occurred while reading the list file:`, error.response ? error.response.statusText : error.message);
                return;
            }

            // Process subdomain enumerations for each URL in the list
            for (const line of lines) {
                await processSubdomainEnumerations(line.trim(), output, recursive, wordlist);
            }
        }
    } catch (error) {
        console.error(`${clc.red('[!]')} Error occurred while processing subdomain enumerations:`, error.response ? error.response.statusText : error.message);
    }
}

// Function to process subdomain enumerations
async function processSubdomainEnumerations(url, outputFile, recursive, wordlist) {
    console.log(`${clc.green('[🔍]')} Start Processing Subdomain Enumerations: ${clc.yellow(`[${url}]`)}`);
    const subdomains = [];
    const {
        dnsenum,
        permutations
    } = argv;

    try {
        const domain = url;

        // Run DNS Cache Snooping
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With DNS Cache Snooping %s`);
        spinner.start();
        const DnscachereconSubdomains = await getSubdomainsFromDNSCache(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from DNS Cache Snooping: ${clc.yellowBright(DnscachereconSubdomains.length)}`);
        subdomains.push(...DnscachereconSubdomains);

        // Run SSL
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With SSL/TLS Certificates %s`);
        spinner.start();
        const SslreconSubdomains = await getSubdomainsFromCertificate(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from SSL/TLS Certificates: ${clc.yellowBright(SslreconSubdomains.length)}`);
        subdomains.push(...SslreconSubdomains);

        // Run BGP Data Analysis
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With BGP Data Analysis %s`);
        spinner.start();
        const BgpreconSubdomains = await getSubdomainsFromRipeData(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from BGP Data Analysis: ${clc.yellowBright(BgpreconSubdomains.length)}`);
        subdomains.push(...BgpreconSubdomains);        

        // Run DNS Dumpster Diving
        //spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With DNS Dumpster Diving %s`);
        //spinner.start();
        //const dnsDumpsterSubdomains = await getSubdomainsFromDnsDumpster(domain);
        //spinner.stop(true);
        //console.log(`${clc.green('[V]')} Total subdomains from DNS Dumpster Diving: ${clc.yellowBright(dnsDumpsterSubdomains.length)}`);
        //subdomains.push(...dnsDumpsterSubdomains);

        // Run subquest
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Subquest %s`);
        spinner.start();

        try {
            const dnsServers = await getDnsServers();
            const foundSubdomains = await getSubDomains(domain, dnsServers);
            spinner.stop(true);
            console.log(`${clc.green('[V]')} Total subdomains from Subquest: ${clc.yellowBright(foundSubdomains.length)}`);
            subdomains.push(...foundSubdomains);
        } catch (error) {
            spinner.stop(true);
            console.error(`[!] Error getting subdomains:`, error.response ? error.response.statusText : error.message);
        }

        // Run Baidu
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Baidu %s`);
        spinner.start();
        const BaidureconSubdomains = await runBaiduSearch(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Baidu: ${clc.yellowBright(BaidureconSubdomains.length)}`);
        subdomains.push(...BaidureconSubdomains);

        // Run Bing
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Bing Engine %s`);
        spinner.start();
        const bingSubdomains = [];

        for (let first = 1; first <= 1000; first += 10) {
        const subdomains = await runBing(domain, first);
        bingSubdomains.push(...subdomains);
        }

        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Bing: ${clc.yellowBright(bingSubdomains.length)}`);
        subdomains.push(...bingSubdomains);

        // Run Anubis DB
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Anubis %s`);
        spinner.start();
        const AnubisreconSubdomains = await runAnubisDB(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Anubis: ${clc.yellowBright(AnubisreconSubdomains.length)}`);
        subdomains.push(...AnubisreconSubdomains);

        // Run Alienvault
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Alienvault %s`);
        spinner.start();
        const AlienreconSubdomains = await fetchAlienVaultSubdomains(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Alienvault: ${clc.yellowBright(AlienreconSubdomains.length)}`);
        subdomains.push(...AlienreconSubdomains);

        // Run crt.sh
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With crt.sh %s`);
        spinner.start();
        const crtshSubdomains = await runCrtsh(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from crt.sh: ${clc.yellowBright(crtshSubdomains.length)}`);
        subdomains.push(...crtshSubdomains);

        // SecurityTrails
        const securityTrailsApiKey = readApiKeys().securitytrails;
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With SecurityTrails %s`);
        spinner.start();
        const securityTrailsSubdomains = await runSecurityTrails(domain, securityTrailsApiKey);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from SecurityTrails: ${clc.yellowBright(securityTrailsSubdomains.length)}`);
        subdomains.push(...securityTrailsSubdomains);

        // Shodan
        const shodanApiKey = readApiKeys().shodan;
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Shodan %s`);
        spinner.start();
        const shodanSubdomains = await runShodan(domain, shodanApiKey);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Shodan: ${clc.yellowBright(shodanSubdomains.length)}`);
        subdomains.push(...shodanSubdomains);

        // Run Amass
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Amass %s`);
        spinner.start();
        const amassSubdomains = await runAmass(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Amass: ${clc.yellowBright(amassSubdomains.length)}`);
        subdomains.push(...amassSubdomains);

        // Run Subfinder
        spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With Subfinder %s`);
        spinner.start();
        const subfinderSubdomains = await runSubfinder(domain);
        spinner.stop(true);
        console.log(`${clc.green('[V]')} Total subdomains from Subfinder: ${clc.yellowBright(subfinderSubdomains.length)}`);
        subdomains.push(...subfinderSubdomains);

        // Run permutations if enabled
        if (permutations) {
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Permutations %s`);
            spinner.start();
            const permutationSubdomains = await generatePermutations(domain);
            spinner.stop(true);
            console.log(`${clc.green('[V]')} Total subdomains from permutations: ${clc.yellowBright(permutationSubdomains.length)}`);
            subdomains.push(...permutationSubdomains);
        }

        // Run dnsenum
        if (dnsenum) {
            //Run dnsenum
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing DNS Enumeration %s`);
            spinner.start();
            const dnsenumSubdomains = await runDnsenum(domain);
            spinner.stop(true);
            console.log(`${clc.green('[V]')} Total subdomains from dnsenum: ${clc.yellowBright(dnsenumSubdomains.length)}`);
            subdomains.push(...dnsenumSubdomains);
            // Run dnsrecon
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Enumerations With DNSSEC Zone Walking %s`);
            spinner.start();
            const dnsreconSubdomains = await runDnsrecon(domain);
            spinner.stop(true);
            console.log(`${clc.green('[V]')} Total subdomains from dnsrecon: ${clc.yellowBright(dnsreconSubdomains.length)}`);
            subdomains.push(...dnsreconSubdomains);
        }

        // Run brute force if wordlist provided or using default wordlist for recursive
        if (recursive || wordlist) {
            spinner.setSpinnerTitle(`${clc.green('[🔍]')} Processing Subdomain Bruteforcing %s`);
            spinner.start();

            let bruteForceSubs;
            if (wordlist) {
                const wordlistPath = path.resolve(wordlist);
                const wordlistContent = fs.readFileSync(wordlistPath, 'utf8');
                const wordlistArray = wordlistContent.split('\n').filter(Boolean);
                console.log(`${clc.green('\n[*]')} Total file wordlist: ${clc.yellowBright(wordlistArray.length)}`);
                bruteForceSubs = await bruteForceSubdomains(domain, wordlistArray);
            } else {
                const defaultWordlistPath = path.join(configDirectory, 'default_wordlist.txt');
                const defaultWordlistContent = fs.readFileSync(defaultWordlistPath, 'utf8');
                const defaultWordlistArray = defaultWordlistContent.split('\n').filter(Boolean);
                console.log(`${clc.green('\n[*]')} Total default wordlist: ${clc.yellowBright(defaultWordlistArray.length)}`);
                bruteForceSubs = await bruteForceSubdomains(domain, defaultWordlistArray);
            }

            spinner.stop(true);
            console.log(`${clc.green('[V]')} Total subdomains from Bruteforce: ${clc.yellowBright(bruteForceSubs.length)}`);
            subdomains.push(...bruteForceSubs);
        }
        await resolveAndSaveSubdomains(domain, outputFile, subdomains);
    } catch (error) {
        console.error(`${clc.red('\n[!]')} Error occurred while processing subdomain enumerations:`, error.response ? error.response.statusText : error.message);
    }

    spinner.stop(true);
}

// Run the main function
main().catch((error) => {
    console.error(`${clc.red('\n[!]')} An error occurred:`, error.response ? error.response.statusText : error.message);
    spinner.stop(true);
});
