=========
Changelog
=========

.. _v0-6-0:

0.6.0 - 2021-05-27
==================

Features
--------

* HTTP(S) (``http``)

  * Headers (``headers``)

    * supports header wire format parsing
    * add parsers for generic headers (\
      `Content-Type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type>`_, \
      `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`_)
    * add parsers for cache related headers (\
      `Age <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Age>`_, \
      `Cache-Control <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>`_, \
      `Date <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date>`_, \
      `ETag <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag>`_, \
      `Expires <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires>`_, \
      `Last-Modified <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified>`_, \
      `Pragma <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma>`_)
    * add parsers for security related headers (\
      `Expect-CT <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT>`_, \
      `Expect-Staple <https://scotthelme.co.uk/designing-a-new-security-header-expect-staple>`_, \
      `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`_, \
      `Strict-Transport-Security <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>`_, \
      `X-Content-Type-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`_, \
      `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>`_)

* TLS (``tls``)

  * Versions (``versions``)

    * add `protocol version 1.3 <https://tools.ietf.org/html/rfc8446>`_ related messages (#20)

  * Cipher Suites (``ciphers``)

    * add `cipher suites <https://tools.ietf.org/html/rfc8446#appendix-B.4>`_ relate to version 1.3 (#20)

  * Diffie-Hellman (``dhparams``)

    * add `supported groups <https://tools.ietf.org/html/rfc8446#section-4.2.7>`_ relate to version 1.3 (#20)

  * Elliptic Curves (``curves``)

    * add `supported groups <https://tools.ietf.org/html/rfc8446#section-4.2.7>`_ relate to version 1.3 (#20)

  * Signature Algorithms (``sigalgos``)

    * add `signature algorithms <https://tools.ietf.org/html/rfc8446#section-4.2.3>`_ relate to version 1.3 (#20)

.. _v0-5-0:

0.5.0 - 2021-04-08
==================

Features
--------

* Generic

  * add parser for `text-based protocols <https://en.wikipedia.org/wiki/Text-based_protocol>`_ (#21)

* SSH (``ssh``)

  * Versions (``versions``)

    * add `protocol version exchange <https://tools.ietf.org/html/rfc4253#section-4.2>`_ related messages (#21)

* SSH 2.0 (``ssh2``)

  * Cipher Suites (``ciphers``)

    * add `algorithm negotiation <https://tools.ietf.org/html/rfc4253#section-7.1>`_ related messages (#21)

Usability
---------

* Generic

  * show attributes in user-friendly order in Markdown output (#30)
  * use human readable algorithms names in Markdown output (#32)
  * add human readable descriptions for exceptions (#33)

.. _v0-4-0:

0.4.0 - 2021-01-30
==================

Features
--------

* TLS (``tls``)

  * Generic

    * add `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`_ related messages (#23)

  * Client Public Key Request (``pubkeyreq``)

    * add `client public key request <https://tools.ietf.org/html/rfc2246#section-7.4.4>`_ related messages (#24)

Improvements
------------

* Generic

  * add `OID <https://en.wikipedia.org/wiki/Object_identifier>`_ to algorithms

.. _v0-3-1:

0.3.1 - 2020-09-15
==================

Features
--------

* Generic

  * `Markdown <https://en.wikipedia.org/wiki/Markdown>`_ serializable format (#19)

Improvements
------------

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * add missing ``ECDHE_PSK`` cipher suites (#7)
    * add `GOST <https://en.wikipedia.org/wiki/GOST>`_ cipher suites
    * add missing draft ECC cipher suites (#9)
    * add missing `FIPS <https://en.wikipedia.org/wiki/FIPS_140-2>`_ cipher suites (#11)
    * add `CECPQ1 <https://en.wikipedia.org/wiki/CECPQ1>`_ cipher suites (#12)
    * add missing `Fortezza <https://en.wikipedia.org/wiki/Fortezza>`_ cipher suites (#13)
    * add missing ``DHE`` cipher suites (#14)
    * add missing SSLv3 cipher suites (#15)

Notable fixes
-------------

* Generic

  * fix unicode string representation in JSON output (#18)

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * fix some cipher suite names and parameters (#7, #10)

.. _v0-3-0:

0.3.0 - 2020-04-30
==================

Features
--------

* TLS (``tls``)

  * protocol item classes for RDP support (#4)
  * `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ calculation
    for TLS client hello (#2)

Bugs
^^^^

* TLS (``tls``)

  * compose all the messages in case of a TLS record (#1)

Refactor
--------

* use attrs to avoid boilerplates (#3)

.. _v0-2-0:

0.2.0 - 2019-12-02
==================

Notable fixes
-------------

* clarify TLS related parameter names
* several packaging fixes

.. _v0-1-0:

0.1.0 - 2019-03-20
==================

Features
--------

* added TLS record protocol support
* added TLS ChangeCipherSpec message support
* added TLS ApplicationData message support
* added TLS handshake message support
* added TLS client
* added SSL support

Improvements
------------

* added serialization support for classes
* added elliptic-curve related descriptive classes
* added timeout parameter to TLS client class
