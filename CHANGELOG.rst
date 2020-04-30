Changelog
=========

.. _v0-3-0:

0.3.0 - 2020-04-30
------------------

Features
^^^^^^^^

* protocol item classes for RDP support (#4)
* `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ calculation
  for TLS client hello (#2)

Bugs
^^^^

* compose all the messages in case of a TLS record (#1)

Refactor
^^^^^^^^

* use attrs to avoid boilerplates (#3)

.. _v0-2-0:

0.2.0 - 2019-12-02
------------------

Bugs
^^^^

* clarify TLS related parameter names
* several packaging fixes
* some minor fixes

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
