# Using the Kali CTF MCP Server with Cursor/Cline

This example demonstrates how to use the Kali CTF MCP server through Cursor/Cline to perform basic network reconnaissance tasks like WHOIS and DNS lookups.

## Prerequisites

1. The Kali CTF MCP server is installed and configured
2. Cursor/Cline is configured to use the MCP server
3. The Kali Linux container is running

## Example 1: WHOIS Lookup

### User Query

```
Can you perform a WHOIS lookup for example.com?
```

### Expected Cursor/Cline Response

```
I'll perform a WHOIS lookup for example.com using the Kali Linux environment.

Using the Kali CTF MCP server to execute the whois command:

Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2023-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrar: ICANN
Registrar IANA ID: 376
Registrar Abuse Contact Email: domain-abuse@icann.org
Registrar Abuse Contact Phone: +1.3103015800
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
DNSSEC DS Data: 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
DNSSEC DS Data: 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2023-09-01T10:11:12Z <<<

The domain example.com is registered with ICANN and has been active since 1995. It's set to expire in August 2024 and has various protection statuses applied to prevent unauthorized changes.
```

## Example 2: DNS Lookup

### User Query

```
Can you do a DNS lookup for google.com?
```

### Expected Cursor/Cline Response

```
I'll perform a DNS lookup for google.com using the Kali Linux environment.

Using the Kali CTF MCP server to execute the dig command:

142.250.190.78
142.250.190.113
142.250.190.102
142.250.190.100
142.250.190.101
142.250.190.139
142.250.190.138
142.250.190.46
142.250.190.110
142.250.190.99

These are the IP addresses associated with google.com. The DNS lookup shows multiple IP addresses because Google uses many servers distributed globally to handle traffic efficiently and provide redundancy.
```

## Example 3: Combined Network Reconnaissance

### User Query

```
Can you perform a basic network reconnaissance on example.org? I'd like to know its IP address, WHOIS information, and any open ports.
```

### Expected Cursor/Cline Response

```
I'll perform a basic network reconnaissance on example.org using the Kali Linux environment.

### 1. DNS Lookup (IP Address)

Using the Kali CTF MCP server to execute the dig command:

93.184.216.34

### 2. WHOIS Information

Using the Kali CTF MCP server to execute the whois command:

Domain Name: EXAMPLE.ORG
Registry Domain ID: D2328855-LROR
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2023-07-06T12:20:39Z
Creation Date: 1995-08-31T04:00:00Z
Registry Expiry Date: 2024-08-30T04:00:00Z
Registrar: Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrar Abuse Contact Email: domain-abuse@icann.org
Registrar Abuse Contact Phone: +1.3103015800
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Registry Registrant ID: 
Registrant Name: ICANN
Registrant Organization: Internet Corporation for Assigned Names and Numbers
Registrant Street: 12025 Waterfront Drive, Suite 300
Registrant City: Los Angeles
Registrant State/Province: CA
Registrant Postal Code: 90094-2536
Registrant Country: US
Registrant Phone: +1.3103015800
Registrant Email: domain-admin@icann.org
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
DNSSEC DS Data: 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
DNSSEC DS Data: 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C

### 3. Port Scan (Top 1000 ports)

Using the Kali CTF MCP server to execute an nmap scan:

Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-01 10:15 UTC
Nmap scan report for example.org (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host) scanned in 21.33 seconds

### Summary

example.org (93.184.216.34) is registered to ICANN and has been active since 1995. The domain has standard protection measures in place to prevent unauthorized changes. The server has two commonly used ports open: 80 (HTTP) and 443 (HTTPS), indicating it's serving web content over both standard and secure connections.
```

## How It Works

When you ask Cursor/Cline to perform these tasks, it uses the MCP server to:

1. Execute commands in the Kali Linux container
2. Capture the output from these commands
3. Process and present the results in a readable format

The MCP server handles all the interaction with the Docker container, making the Kali Linux tools seamlessly available to the AI assistant.
