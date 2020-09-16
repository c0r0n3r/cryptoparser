Changelog
=========

.. _v0-3-1:

0.3.1 - 2020-09-15
------------------

Features
^^^^^^^^

* Generic

  * `Markdown <https://en.wikipedia.org/wiki/Markdown>`_ serializable format (#19)

Improvements
^^^^^^^^^^^^

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
^^^^^^^^^^^^^

* Generic

  * fix unicode string representation in JSON output (#18)

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * fix some cipher suite names and parameters (#7, #10)

.. _v0-3-0:

0.3.0 - 2020-04-30
------------------

Features
^^^^^^^^

* TLS (``tls``)

  * protocol item classes for RDP support (#4)
  * `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ calculation
    for TLS client hello (#2)

Bugs
^^^^

* TLS (``tls``)

  * compose all the messages in case of a TLS record (#1)

Refactor
^^^^^^^^

* use attrs to avoid boilerplates (#3)

.. _v0-2-0:

0.2.0 - 2019-12-02
------------------

Notable fixes
^^^^^^^^^^^^^

* clarify TLS related parameter names
* several packaging fixes

.. _v0-1-0:

0.1.0 - 2019-03-20
------------------

Features
^^^^^^^^

* added TLS record protocol support
* added TLS ChangeCipherSpec message support
* added TLS ApplicationData message support
* added TLS handshake message support
* added TLS client
* added SSL support

Improvements
^^^^^^^^^^^^

* added serialization support for classes
* added elliptic-curve related descriptive classes
* added timeout parameter to TLS client class
