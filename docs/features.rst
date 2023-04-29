Features
--------

Supported Protocols
^^^^^^^^^^^^^^^^^^^

Secure Shell (SSH)
""""""""""""""""""

-  `SSH 2.0 <https://tools.ietf.org/html/rfc4253>`__

Secure Socket Layer (SSL)
"""""""""""""""""""""""""

-  `SSL 2.0 <https://tools.ietf.org/html/draft-hickman-netscape-ssl-00>`__
-  `SSL 3.0 <https://tools.ietf.org/html/rfc6101>`__

Transport Layer Security (TLS)
""""""""""""""""""""""""""""""

-  `TLS 1.0 <https://tools.ietf.org/html/rfc2246>`__
-  `TLS 1.1 <https://tools.ietf.org/html/rfc4346>`__
-  `TLS 1.2 <https://tools.ietf.org/html/rfc5246>`__
-  `TLS 1.3 <https://tools.ietf.org/html/rfc8446>`__

Protocol Specific Features
^^^^^^^^^^^^^^^^^^^^^^^^^^

Hypertext Transfer Protocol (HTTP)
""""""""""""""""""""""""""""""""""

1. supports header wire format parsing
2. supports detailed parsing of generic headers
   (`Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`__,
   `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`__)
3. supports detailed parsing of caching headers
   (`Age <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age>`__,
   `Cache-Control <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>`__,
   `Date <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date>`__,
   `ETag <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag>`__,
   `Expires <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires>`__,
   `Last-Modified <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified>`__,
   `Pragma <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma>`__)
4. supports detailed parsing of security headers
   (`Expect-CT <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT>`__,
   `Expect-Staple <https://scotthelme.co.uk/designing-a-new-security-header-expect-staple>`__,
   `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`__,
   `Strict-Transport-Security <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>`__,
   `X-Content-Type-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`__,
   `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>`__)

Transport Layer Security (TLS)
""""""""""""""""""""""""""""""

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

   - supports TLS handshake-related `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__ messages

Secure Shell (SSH)
""""""""""""""""""

-  cipher suites

   1. identifies as much encryption algorithms as possible (more than 200, compared to 70+ currently supported by
      OpenSSH)
   2. supports `HASSH fingerprint <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__ calculation
      (#96)

-  public keys

   1. supports host keys and cretificates (both ``V00`` and ``V01``)
