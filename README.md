# ACME client
An application that implements Automatic Certificate Management Environment (ACME) ([RFC8555](https://tools.ietf.org/html/rfc8555)).
This is a personal project for the course Network Security 2023 at ETH Zurich. It contains the necessary functionalities to request and obtain certificates using the ACME protocol.

## Components
- *ACME client:* An ACME client which can interact with a standard-conforming ACME server.
- *DNS server:* A DNS server which resolves the DNS queries of the ACME server.
- *Challenge HTTP server:* An HTTP server to respond to http-01 queries of the ACME server.
- *Certificate HTTPS server:* An HTTPS server which uses a certificate obtained by the ACME client.
- *Shutdown HTTP server:*  An HTTP server to receive a shutdown signal.

## Functionalities
- use ACME to request and obtain certificates using the `dns-01` and `http-01` challenge (with fresh keys in every run),
- request and obtain certificates which contain aliases,
- request and obtain certificates with wildcard domain names, and
- revoke certificates after they have been issued by the ACME server.

## ACME server
As this project only contains the ACME client, I used a pebble server which acts as an ACME server. 
To start a pebble server run
```
pebble -config ./test/config/pebble-config.json -dnsserver 127.0.0.1:10053
```
See more here: https://github.com/letsencrypt/pebble.

## ACME client
#### Command-line arguments <a name="arguments"></a>
The application supports the following command-line arguments (passed to the `run` file):

**Positional arguments:**
- `Challenge type`
_(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**
- `--dir DIR_URL`
_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS` 
_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries. 
- `--domain DOMAIN`
_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.

**Example:**
Consider the following invocation of `run`:
```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
```
