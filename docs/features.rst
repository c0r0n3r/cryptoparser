--------
Features
--------

Supported Protocols
===================

Secure Shell (SSH)
------------------

-  `SSH 2.0 <https://tools.ietf.org/html/rfc4253>`__

Secure Socket Layer (SSL)
-------------------------

-  `SSL 2.0 <https://tools.ietf.org/html/draft-hickman-netscape-ssl-00>`__
-  `SSL 3.0 <https://tools.ietf.org/html/rfc6101>`__

Transport Layer Security (TLS)
------------------------------

-  `TLS 1.0 <https://tools.ietf.org/html/rfc2246>`__
-  `TLS 1.1 <https://tools.ietf.org/html/rfc4346>`__
-  `TLS 1.2 <https://tools.ietf.org/html/rfc5246>`__
-  `TLS 1.3 <https://tools.ietf.org/html/rfc8446>`__

Domain Name System (DNS)
------------------------

-  `DNSSEC <https://www.rfc-editor.org/rfc/rfc4034>`__ (Domain Name System Security Extensions)

Protocol Specific Features
==========================

Hypertext Transfer Protocol (HTTP)
----------------------------------

1. supports header wire format parsing
2. supports detailed parsing of generic headers
   (`Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`__,
   `NEL <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL>`__ (Network Error Logging),
   `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`__,
   `Set-Cookie <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>`__)
3. supports detailed parsing of caching headers
   (`Age <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age>`__,
   `Cache-Control <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>`__,
   `Date <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date>`__,
   `ETag <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag>`__,
   `Expires <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires>`__,
   `Last-Modified <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified>`__,
   `Pragma <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma>`__)
4. supports detailed parsing of security headers
   (`Content Security Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>`__ (CSP),
   `Content-Security-Policy-Report-Only <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only>`__,
   `Expect-CT <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT>`__,
   `Expect-Staple <https://scotthelme.co.uk/designing-a-new-security-header-expect-staple>`__,
   `HTTP Public Key Pinning <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`__ (HPKP),
   `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`__,
   `Strict-Transport-Security <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>`__,
   `X-Content-Type-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`__,
   `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>`__,
   `X-XSS-Protection <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection>`__)

Transport Layer Security (TLS)
------------------------------

Only features that cannot be or difficultly implemented by some of the most popular SSL/TLS implementations (eg:
`GnuTls <https://www.gnutls.org/>`__, `LibreSSL <https://www.libressl.org/>`__, `OpenSSL <https://www.openssl.org/>`__,
`wolfSSL <https://www.wolfssl.com/>`__, ...) are listed.

-  generic

   1. supports
      `Generate Random Extensions And Sustain Extensibility <https://tools.ietf.org/html/draft-ietf-tls-grease-04>`__
      (GREASE) values for

      -  protocol version
      -  extension type
      -  ciphers suite
      -  signature algorithms
      -  named group

   2. supports easy
      `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__
      generation

-  protocol versions

   1. support not only the final, but also draft versions

-  cipher suites

   1. supports each cipher suites discussed on `ciphersuite.info <https://ciphersuite.info>`__
   2. supports `GOST <https://en.wikipedia.org/wiki/GOST>`__ (national standards of the Russian Federation and CIS
      countries) cipher suites

-  application layer

   - supports TLS handshake-related `MySQL <https://en.wikipedia.org/wiki/MySQL>`__ messages
   - supports TLS handshake-related `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__ messages
   - supports TLS handshake-related `PostgreSQL <https://en.wikipedia.org/wiki/PostgreSQL>`__ messages
   - supports TLS handshake-related `RDP <https://en.wikipedia.org/wiki/Remote_Desktop_Protocol`__ messages

Secure Shell (SSH)
------------------

-  cipher suites

   1. identifies as much encryption algorithms as possible (more than 200, compared to 70+ currently supported by
      OpenSSH)
   2. supports `HASSH fingerprint <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__ calculation

-  public keys

   1. supports host keys, cretificates (both ``V00`` and ``V01``), X.509 certificates and chains

Domain Name System (DNS)
------------------------

-  e-mail authentication, reporting

   -  `Domain-based Message Authentication, Reporting, and Conformance <https://www.rfc-editor.org/rfc/rfc7489>`__
      (DMARC)
   -  `Sender Policy Framework <https://www.rfc-editor.org/rfc/rfc7208>`__ (SPF)
   -  `SMTP MTA Strict Transport Security <https://www.rfc-editor.org/rfc/rfc8461>`__ (MTA-STS)
   -  `SMTP TLS Reporting <https://www.rfc-editor.org/rfc/rfc8460>`__ (TLSRPT)

-  DNSSEC (Domain Name System Security Extensions)

   -  `DNSKEY <https://www.rfc-editor.org/rfc/rfc4034#section-2>`__
   -  `DS <https://www.rfc-editor.org/rfc/rfc4034#section-5>`__
   -  `RRSIG <https://www.rfc-editor.org/rfc/rfc4034#section-3>`__
