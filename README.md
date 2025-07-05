# BIMI-agent

[![Build Status](https://ci.rspamd.com/api/badges/rspamd/bimi-helper/status.svg)](https://ci.rspamd.com/rspamd/bimi-helper)

This service is intended to assist in extraction of the [BIMI VMC](https://bimigroup.org/verified-mark-certificates-vmc-and-bimi/)
certificates, validate them using various rules and  a set of trusted 
fingerprints or system CA roots, extract image (from LOGOTYPE X.509 extension) and
store that image in Redis.

## Usage

```commandline
bimi-agent 0.2.0
BIMI agent to assist images verification end extraction

USAGE:
    bimi-agent [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Verbose level (repeat for more verbosity)

OPTIONS:
        --cert <cert>                              X509 certificate for HTTP server
        --chroot <chroot>                          Chroot to this directory
        --redis-expiry <expiry>                     [default: 259200]
    -F, --fingerprint <fingerprints>...            Trusted fingerprint
        --fingerprints-file <fingerprints-file>    Trusted fingerprints file
    -g, --group <group>                            Run as this group
    -t, --timeout <http-timeout>                   HTTP client timeout [default: 5.0]
    -U, --user-agent <http-ua>                     HTTP user agent [default: BIMI-Agent/0.1]
    -l, --listen <listen-addr>                     Listen address to bind to [default: 0.0.0.0:3030]
    -n, --max-threads <max-threads>                Number of threads to start [default: 2]
        --redis-prefix <prefix>                    Prefix for Redis keys (if not specified in a request)
        --privkey <privkey>                        Private key for SSL HTTP server
        --redis-timeout <timeout>                  Redis operations timeout [default: 5.0]
    -u, --user <user>                              Run as this user and their primary group
```

This will open an HTTP server available for requests.

For example, store an image in Redis:

```commandline
 curl -X POST 'http://localhost:3030/v1/check/' \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://amplify.valimail.com/bimi/valimail/dcvSV-hEXmW-valimail_inc_164268123.pem", "redis_server": "redis://127.0.0.1", "domain": "valimail.com"}'
```

Unfortunately, VMC root CA are not in the chains of trust so far, so this app
allows specifying trusted fingerprints. In this mode, when BIMI-helper observes
a CA certificate it tries to verify it's SHA256 digest against a set of trusted
fingerprints.

For the example above, you might want to add DigiCert Verified Mark Root CA fingerprint
to be able to validate pem from `valimail`. 

## Use in Docker

This app can be built and used via Docker.

```commandline
docker build -t bimi-agent .
docker run -p 3030:3030 -d --rm --name bimi-agent bimi-agent
```

## Valid VMC roots fingerprints

So far, there are five valid VMC roots:

* Digicert VMC CA: `504386c9ee8932fecc95fade427f69c3e2534b7310489e300fee448e33c46b42`
* Entrust Verified Mark Root Certification Authority - VMCR1: `7831d95a47d42508cd5c9e6264f9096bac19f04eb9b7c8bdd35fffc71c189617`
* SSL.com VMC RSA Root CA 2024: `8f9d1b7698886782a599b48510651c66a1aa0c5ca3192097bdc68534154bd30d`
* SSL.com VMC ECC Root CA 2024: `1b82e7f4910b51e3e802a493acdc17ff58eac8b9eb7c09b52ac6cd2efb83598c`
* GlobalSign Verified Mark Root R42: `cd122cb877c6928b9017b0f0b80dbd508196300bbd03cd7356c3beef524e7e0b`
