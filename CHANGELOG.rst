=========
Changelog
=========

-------------------
0.12.1 - 2023-12-13
-------------------

Notable fixes
=============

-  SSH

   -  add missing host key algorithms to key parser classes (#79)

-  Generic

   -  fix markdown generation in the case of TLS client versions (#80)

-------------------
0.12.0 - 2023-11-23
-------------------

Features
========

-  HTTP(S) (``http``)

   -  Headers (``headers``)

      -  add parsers for security related headers
         (`Content Security Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>`__ (CSP),
         `Content-Security-Policy-Report-Only <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only>`__)
         (#59)


-------------------
0.11.2 - 2023-11-13
-------------------

Features
========

-  HTTP(S) (``http``)

   -  Headers (``headers``)

      -  add parsers for generic headers
         (`NEL <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/NEL>`__ (Network Error Logging),
         `Set-Cookie <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>`__)
      -  add parsers for security related headers
         (`HTTP Public Key Pinning <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`__ (HPKP),
         `X-XSS-Protection <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection>`__)

Improvements
============

-  HTTP(S) (``http``)

   -  Headers (``headers``)

      -  implement detailed parsing of
         `Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`__ header

-------------------
0.11.1 - 2023-11-06
-------------------

Features
========

-  SSH (``ssh``)

   -  Public Keys (``pubkeys``)

      -  add X.509 certificate and certificate chain related classes (#63)

-------------------
0.11.0 - 2023-10-28
-------------------

Features
========

-  Generic

   - add post processing capability to Markdown output (#73)
   - use class give grade for public keys (#73)

-------------------
0.10.3 - 2023-10-12
-------------------

Notable fixes
=============

-  Generic

   -  add missing dnsrec module to the packaging (#75)

-------------------
0.10.2 - 2023-08-28
-------------------

Features
========

-  DNS

   -  add parser for e-mail authentication and reporting related records (#74, #35, #36, #37, #38)

      -  `mail exchange <https://www.rfc-editor.org/rfc/rfc1035>`__ (MX)
      -  `Domain-based Message Authentication, Reporting, and Conformance <https://www.rfc-editor.org/rfc/rfc7489>`__
         (DMARC)
      -  `Sender Policy Framework <https://www.rfc-editor.org/rfc/rfc7208>`__ (SPF)
      -  `SMTP MTA Strict Transport Security <https://www.rfc-editor.org/rfc/rfc8461>`__ (MTA-STS)
      -  `SMTP TLS Reporting <https://www.rfc-editor.org/rfc/rfc8460>`__ (TLSRPT)

-------------------
0.10.1 - 2023-08-29
-------------------

Features
========

-  DNS

   -  add parser for DNSSEC-related records (#72)

      -  `DNSKEY <https://www.rfc-editor.org/rfc/rfc4034#section-2>`__
      -  `DS <https://www.rfc-editor.org/rfc/rfc4034#section-5>`__
      -  `RRSIG <https://www.rfc-editor.org/rfc/rfc4034#section-3>`__

-------------------
0.10.0 - 2023-08-03
-------------------

Notable fixes
=============

-  Generic

   -  Markdown output of attr-based classes

------------------
0.9.1 - 2022-06-22
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  add parser for `signed certificate timestamp <https://www.rfc-editor.org/rfc/rfc6962.html#section-3.3.1>`__
         entries (#52)

------------------
0.9.0 - 2023-04-29
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  protocol item classes for `OpenVPN <https://en.wikipedia.org/wiki/OpenVPN>`__ support (#62)

------------------
0.8.5 - 2023-04-02
------------------

Features
========

-  Generic

   -  move data classes to `CryptoDataHub repository <https://gitlab.com/coroner/cryptodatahub>`__ (#67)

------------------
0.8.4 - 2023-01-22
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  protocol item classes for MySQL support (#61)

------------------
0.8.2 - 2022-10-10
------------------

Features
========

-  TLS (``tls``)

   -  Cipher Suites (``ciphers``)

      -  add OpenSSL names (#54)
      -  add min/max versions (#55)

-  SSH (``ssh``)

   -  Public Keys (``pubkeys``)

      -  `HASSH fingerprint <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__ calculation (#48)
      -  add `host certificate <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys>`__ related
         classes (#53)

------------------
0.8.0 - 2022-01-18
------------------

Features
========

-  SSH (``ssh``)

   -  Public Keys (``pubkeys``)

      -  add `public key <https://datatracker.ietf.org/doc/html/rfc4253#section-6.6>`__ related classes (#43)

   -  Versions (``versions``)

      -  add `software version <https://tools.ietf.org/html/rfc4253#section-4.2>`__ related classes (#46)

------------------
0.7.3 - 2021-12-26
------------------

Notable fixes
=============

-  Generic

   -  Fix time zone handlind in datetime parser

------------------
0.7.2 - 2021-10-07
------------------

Other
=====

-  switch to Markdown format in changelog, readme and contributing
-  update contributing to the latest version from contribution-guide.org

------------------
0.7.1 - 2021-09-20
------------------

Features
========

-  TLS (``tls``)

   -  protocol item classes for PostgreSQL support (#44)

------------------
0.7.0 - 2021-09-02
------------------

Features
========

-  TLS (``tls``)

   -  Extensions (``extensions``)

      -  add `application-layer protocol negotiation <https://www.rfc-editor.org/rfc/rfc5077.html>`__ extension related
         messages (#40)
      -  add `encrypt-then-MAC <https://www.rfc-editor.org/rfc/rfc7366.html>`__ extension related messages (#40)
      -  add `extended master secret <https://www.rfc-editor.org/rfc/rfc7627.html>`__ extension related messages (#40)
      -  add `next protocol negotiation <https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html>`__ extension
         related messages (#40)
      -  add `renegotiation indication <https://www.rfc-editor.org/rfc/rfc5746.html>`__ extension related messages (#40)
      -  add `session ticket <https://www.rfc-editor.org/rfc/rfc5077.html>`__ extension related messages (#40)

------------------
0.6.0 - 2021-05-27
------------------

Features
========

-  HTTP(S) (``http``)

   -  Headers (``headers``)

      -  supports header wire format parsing
      -  add parsers for generic headers
         (`Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`__,
         `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`__)
      -  add parsers for cache related headers (`Age <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age>`__,
         `Cache-Control <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>`__,
         `Date <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date>`__,
         `ETag <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag>`__,
         `Expires <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires>`__,
         `Last-Modified <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified>`__,
         `Pragma <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma>`__)
      -  add parsers for security related headers
         (`Expect-CT <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT>`__,
         `Expect-Staple <https://scotthelme.co.uk/designing-a-new-security-header-expect-staple>`__,
         `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`__,
         `Strict-Transport-Security <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>`__,
         `X-Content-Type-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`__,
         `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>`__)

-  TLS (``tls``)

   -  Versions (``versions``)

      -  add `protocol version 1.3 <https://tools.ietf.org/html/rfc8446>`__ related messages (#20)

   -  Cipher Suites (``ciphers``)

      -  add `cipher suites <https://tools.ietf.org/html/rfc8446#appendix-B.4>`__ relate to version 1.3 (#20)

   -  Diffie-Hellman (``dhparams``)

      -  add `supported groups <https://tools.ietf.org/html/rfc8446#section-4.2.7>`__ relate to version 1.3 (#20)

   -  Elliptic Curves (``curves``)

      -  add `supported groups <https://tools.ietf.org/html/rfc8446#section-4.2.7>`__ relate to version 1.3 (#20)

   -  Signature Algorithms (``sigalgos``)

      -  add `signature algorithms <https://tools.ietf.org/html/rfc8446#section-4.2.3>`__ relate to version 1.3 (#20)

------------------
0.5.0 - 2021-04-08
------------------

Features
========

-  Generic

   -  add parser for `text-based protocols <https://en.wikipedia.org/wiki/Text-based_protocol>`__ (#21)

-  SSH (``ssh``)

   -  Versions (``versions``)

      -  add `protocol version exchange <https://tools.ietf.org/html/rfc4253#section-4.2>`__ related messages (#21)

-  SSH 2.0 (``ssh2``)

   -  Cipher Suites (``ciphers``)

      -  add `algorithm negotiation <https://tools.ietf.org/html/rfc4253#section-7.1>`__ related messages (#21)

Usability
=========

-  Generic

   -  show attributes in user-friendly order in Markdown output (#30)
   -  use human readable algorithms names in Markdown output (#32)
   -  add human readable descriptions for exceptions (#33)

------------------
0.4.0 - 2021-01-30
------------------

Features
========

-  TLS (``tls``)

   -  Generic

      -  add `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`__ related messages (#23)

   -  Client Public Key Request (``pubkeyreq``)

      -  add `client public key request <https://tools.ietf.org/html/rfc2246#section-7.4.4>`__ related messages (#24)

Improvements
============

-  Generic

   -  add `OID <https://en.wikipedia.org/wiki/Object_identifier>`__ to algorithms

------------------
0.3.1 - 2020-09-15
------------------

Features
========

-  Generic

   -  `Markdown <https://en.wikipedia.org/wiki/Markdown>`__ serializable format (#19)

Improvements
============

-  TLS (``tls``)

   -  Cipher Suites (``ciphers``)

      -  add missing ``ECDHE_PSK`` cipher suites (#7)
      -  add `GOST <https://en.wikipedia.org/wiki/GOST>`__ cipher suites
      -  add missing draft ECC cipher suites (#9)
      -  add missing `FIPS <https://en.wikipedia.org/wiki/FIPS_140-2>`__ cipher suites (#11)
      -  add `CECPQ1 <https://en.wikipedia.org/wiki/CECPQ1>`__ cipher suites (#12)
      -  add missing `Fortezza <https://en.wikipedia.org/wiki/Fortezza>`__ cipher suites (#13)
      -  add missing ``DHE`` cipher suites (#14)
      -  add missing SSLv3 cipher suites (#15)

Notable fixes
=============

-  Generic

   -  fix unicode string representation in JSON output (#18)

-  TLS (``tls``)

   -  Cipher Suites (``ciphers``)

      -  fix some cipher suite names and parameters (#7, #10)

------------------
0.3.0 - 2020-04-30
------------------

Features
========

-  TLS (``tls``)

   -  protocol item classes for RDP support (#4)
   -  `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__
      calculation for TLS client hello (#2)

Notable fixes
=============

-  TLS (``tls``)

   -  compose all the messages in case of a TLS record (#1)

Refactor
========

-  use attrs to avoid boilerplates (#3)

------------------
0.2.0 - 2019-12-02
------------------

Notable fixes
=============

-  clarify TLS related parameter names
-  several packaging fixes

------------------
0.1.0 - 2019-03-20
------------------

Features
========

-  added TLS record protocol support
-  added TLS ChangeCipherSpec message support
-  added TLS ApplicationData message support
-  added TLS handshake message support
-  added TLS client
-  added SSL support

Improvements
============

-  added serialization support for classes
-  added elliptic-curve related descriptive classes
-  added timeout parameter to TLS client class
