CryptoParser
============

What is it and what is it not?
------------------------------

As the project name CryptoParser implies, it is a cryptographic protocol parser. The main purpose of creating this
library is the fact, that cryptography protocol analysis differs in many aspect from establishing a connection using a 
cryptographic protocol.  Analysis is mostly testing where we trigger special and corner cases of the protocol and we 
also trying to establish connection with hardly supported, experimental, obsoleted or even deprecated mechanisms or 
algorithms which are may or may not supported by the latest or any version of an implementation of the cryptographic 
protocol.

As follows, it is neither a comprehensive nor a secure implementation of any cryptographic protocol. On the one hand
library implements only the absolutely necessary parts of the protocol. On the other it contains completely insecure
algorithms and mechanisms. It is not designed and contraindicated to use this library establishing secure connections.
If you are searching for cryptographic protocol implementation, there are several existing wrappers and native
implementations for Python (eg: M2Crypto, pyOpenSSL, Paramiko, ...).

Quick start
-----------

CryptoParser can be installed directly via pip:

::

    pip install cryptoparser

Development environment
-----------------------

If you want to setup a development environment, you are in need of `pipenv <https://docs.pipenv.org/>`_.

::

    $ cd cryptoparser
    $ pipenv install --dev
    $ pipenv shell


Features
--------

Protocols
^^^^^^^^^

* Secure Socket Layer (SSL)

  * `SSL 2.0 <https://tools.ietf.org/html/draft-hickman-netscape-ssl-00>`_
  * `SSL 3.0 <https://tools.ietf.org/html/rfc6101>`_

* Transport Layer Security (TLS)

  * `TLS 1.0 <https://tools.ietf.org/html/rfc2246>`_
  * `TLS 1.1 <https://tools.ietf.org/html/rfc4346>`_
  * `TLS 1.2 <https://tools.ietf.org/html/rfc5246>`_

Python implementation
^^^^^^^^^^^^^^^^^^^^^

* CPython (2.7, >=3.3)
* PyPy (2.7, 3.5)

Operating systems
^^^^^^^^^^^^^^^^^

* Linux
* macOS
* Windows

License
-------

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2.0 can be found at `Choose an open source
license <https://choosealicense.com/licenses#mpl-2.0>`__ website.
