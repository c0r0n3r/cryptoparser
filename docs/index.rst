.. meta::
    :google-site-verification:
        2AAgZNptPaMHxDeXJegA8i8aW1jURVBpQseacnHQr8Q

.. meta::
    :description:
        An analysis oriented security protocol parser and generator

.. meta::
    :keywords:
        cryptoparser,cryptolyzer,cryptography,cryptographic algorithms,tls handdhake,ssl handdhake,ssh handdhake,
        starttls,opportunistic tls,ssh host keys,ssh host certificates,http caching headers,http security header,
        dnssec records,email authentication

.. meta::
    :author:
        Szilárd Pfeiffer

=======
Summary
=======

.. include:: ../README.rst

=======
Details
=======

The main purpose of creating this library is the fact, that cryptography protocol analysis differs in many aspect from
establishing a connection using a cryptographic protocol. Analysis is mostly testing where we trigger special and corner
cases of the protocol and we also trying to establish connection with hardly supported, experimental, obsoleted or even
deprecated mechanisms or algorithms which are may or may not supported by the latest or any version of an implementation
of the cryptographic protocol.

One the one hand it is neither a comprehensive nor a secure implementation of any cryptographic protocol. On the one
hand library implements only the absolutely necessary parts of the protocol. On the other it contains completely insecure
algorithms and mechanisms. It is not designed and contraindicated to use this library establishing secure connections.
If you are searching for cryptographic protocol implementation, there are several existing wrappers and native
implementations for Python (eg: M2Crypto, pyOpenSSL, Paramiko, ...).

.. toctree::
    :maxdepth: 3

    features
    development

=======
History
=======

.. toctree::
    :maxdepth: 2

    changelog
