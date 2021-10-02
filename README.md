# CryptoParser

## What is it and what is it not?

As the project name CryptoParser implies, it is a cryptographic protocol parser. The main purpose of creating this
library is the fact, that cryptography protocol analysis differs in many aspect from establishing a connection using a
cryptographic protocol. Analysis is mostly testing where we trigger special and corner cases of the protocol and we also
trying to establish connection with hardly supported, experimental, obsoleted or even deprecated mechanisms or
algorithms which are may or may not supported by the latest or any version of an implementation of the cryptographic
protocol.

As follows, it is neither a comprehensive nor a secure implementation of any cryptographic protocol. On the one hand
library implements only the absolutely necessary parts of the protocol. On the other it contains completely insecure
algorithms and mechanisms. It is not designed and contraindicated to use this library establishing secure connections.
If you are searching for cryptographic protocol implementation, there are several existing wrappers and native
implementations for Python (eg: M2Crypto, pyOpenSSL, Paramiko, \...).

## Quick start

CryptoParser can be installed directly via pip:

```shell
$ pip install cryptoparser
```

## Development environment

If you want to setup a development environment, you are in need of [pipenv](https://docs.pipenv.org/).

```shell
$ cd cryptoparser
$ pipenv install --dev
$ pipenv shell
```

## Features

### Protocols

- Secure Shell (SSH)
  - [SSH 2.0](https://tools.ietf.org/html/rfc4253)
- Secure Socket Layer (SSL)
  - [SSL 2.0](https://tools.ietf.org/html/draft-hickman-netscape-ssl-00)
  - [SSL 3.0](https://tools.ietf.org/html/rfc6101)
- Transport Layer Security (TLS)
  - [TLS 1.0](https://tools.ietf.org/html/rfc2246)
  - [TLS 1.1](https://tools.ietf.org/html/rfc4346)
  - [TLS 1.2](https://tools.ietf.org/html/rfc5246)
  - [TLS 1.3](https://tools.ietf.org/html/rfc8446)

### Python implementation

- CPython (2.7, \>=3.3)
- PyPy (2.7, 3.5)

### Operating systems

- Linux
- macOS
- Windows

## Protocol Specific Features

### Hypertext Transfer Protocol (HTTP)

#### Headers

1.  supports header wire format parsing
2.  supports detailed parsing of generic headers
    ([Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type),
    [Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server))
3.  supports detailed parsing of caching headers ([Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age),
    [Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control),
    [Date](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date),
    [ETag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag),
    [Expires](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires),
    [Last-Modified](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified),
    [Pragma](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma))
4.  supports detailed parsing of security headers
    ([Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT),
    [Expect-Staple](https://scotthelme.co.uk/designing-a-new-security-header-expect-staple),
    [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy),
    [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security),
    [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options),
    [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options))

### Transport Layer Security (TLS)

Only features that cannot be or difficultly implemented by some of the most popular SSL/TLS implementations (eg:
[GnuTls](https://www.gnutls.org/), [LibreSSL](https://www.libressl.org/), [OpenSSL](https://www.openssl.org/),
[wolfSSL](https://www.wolfssl.com/), \...) are listed.

#### Generic

1.  supports [Generate Random Extensions And Sustain
    Extensibility](https://tools.ietf.org/html/draft-ietf-tls-grease-04) (GREASE) values for
    - protocol version
    - extension type
    - ciphers suite
    - signature algorithms
    - named group
2.  supports easy [JA3
    fingerprint](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967) generation

#### Protocol Versions

1.  support not only the final, but also draft versions

#### Cipher Suites

1.  supports each cipher suites discussed on [ciphersuite.info](https://ciphersuite.info)
2.  supports [GOST](https://en.wikipedia.org/wiki/GOST) (national standards of the Russian Federation and CIS countries)
    cipher suites

### Secure Shell (SSH)

#### Cipher Suites

1.  identifies as much encryption algorithms as possible (more than 200, compared to 70+ currently supported by OpenSSH)

## License

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2.0 can be found at [Choose an open source
license](https://choosealicense.com/licenses#mpl-2.0) website.
