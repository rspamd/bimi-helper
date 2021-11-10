# BIMI-agent

This service is intended to assist in extraction of the [BIMI VMC](https://bimigroup.org/verified-mark-certificates-vmc-and-bimi/)
certificates, validate them using various rules and  a set of trusted 
fingerprints or system CA roots, extract image (from LOGOTYPE X.509 extension) and
store that image in Redis.

So far, this project is highly experimental (as BIMI overall) and it **should not**
be used in the production environment.

## Usage

```commandline
bimi-agent 0.1.0
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
 curl -X POST 'http://localhost:3030/check/' \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://amplify.valimail.com/bimi/valimail/dcvSV-hEXmW-valimail_inc_164268123.pem", "redis_server": "redis://127.0.0.1", "domain": "valimail.com"}'
```

Unfortunately, VMC root CA are not in the chains of trust so far, so this app
allows specifying trusted fingerprints. In this mode, when BIMI-helper observes
a CA certificate it tries to verify it's SHA256 digest against a set of trusted
fingerprints.

For the example above, you might want to add DigiCert Verified Mark Root CA fingerprint
to be able to validate pem from `valimail`. 

## Valid VMC roots fingerprints

So far, there are two valid VMC roots:
* Digicert VMC CA: `504386c9ee8932fecc95fade427f69c3e2534b7310489e300fee448e33c46b42`
* Entrust VMC (is not included in chains...)

## TODO list

- [x] Implement the basic prototype
- [x] Add x509 extraction and checks
- [x] Add oids specific for BIMI Extended Key Usage
- [x] Implement a simple extractor for LOGOTYPE images asn.1 structure
- [x] Implement storage for BIMI images in Redis
- [x] Write tests
- [x] Implement reading from a file with trusted fingerprints
- [ ] Add systemd units and other helping stuff
- [x] Add integration to Rspamd
- [x] Work with plain SVG images from `l=` anchor in BIMI records
- [ ] Validate SVG images
- [ ] Work with remote images (e.g. with no `data:` URLs)
- [ ] Refactor ugly code