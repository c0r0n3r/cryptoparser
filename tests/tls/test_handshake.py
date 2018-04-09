#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import datetime
import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsHandshakeServerHello, TlsHandshakeHelloRandom, TlsCipherSuiteVector, TlsCompressionMethodVector, TlsCompressionMethod, TlsSessionIdVector, TlsExtensions
from cryptoparser.tls.subprotocol import TlsHandshakeCertificate, TlsCertificates, TlsCertificate
from cryptoparser.tls.subprotocol import TlsHandshakeServerHelloDone
from cryptoparser.tls.subprotocol import SslHandshakeClientHello, SslHandshakeServerHello
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal


class TestTlsHandshakeClientHello(unittest.TestCase):
    def setUp(self):
        self.client_hello_minimal_bytes = bytes(
            b'\x01'                             + # handshake_type = CLIENT_HELLO
            b'\x00\x00\x39'                     + # length = 0x39
            b'\x03\x03'                         + # version = TLS1_2
            b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' + # time + random
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00'                             + # session_id_length
            b'\x00\x10'                         + # cipher_suite_length
            b'\x00\x00\x00\x01\x00\x02\x00\x03' + # cipher_suites
            b'\x00\x04\x00\x05\x00\x06\x00\x07' +
            b'\x01'                             + # compression_method_length
            b'\x00'                             + # compression_methods
            b'\x00\x00'                         + # extension_length
            b''
        )

        self.client_hello_minimal = TlsHandshakeClientHello(
            TlsCipherSuiteVector([
                TlsCipherSuite.TLS_NULL_WITH_NULL_NULL,
                TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
                TlsCipherSuite.TLS_RSA_WITH_NULL_SHA,
                TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                TlsCipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA
            ]),
            TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                datetime.datetime(2018, 8, 10, tzinfo=None),
                b'\x04\x05\x06\x07' + 
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x01\x02\x03\x04\x05\x06\x07',
            ),
            TlsSessionIdVector([]),
            TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
            TlsExtensions([]),
        )

    def test_parse(self):
        client_hello_minimal = TlsHandshakeClientHello.parse_exact_size(self.client_hello_minimal_bytes)

        self.assertEqual(
            client_hello_minimal.protocol_version,
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            client_hello_minimal.random,
            self.client_hello_minimal.random
        )
        self.assertEqual(
            client_hello_minimal.cipher_suites,
            self.client_hello_minimal.cipher_suites
        )
        self.assertEqual(
            client_hello_minimal.compression_methods,
            self.client_hello_minimal.compression_methods
        )
        self.assertEqual(
            client_hello_minimal.extensions,
            self.client_hello_minimal.extensions
        )

    def test_compose(self):
        self.assertEqual(
            self.client_hello_minimal.compose(),
            self.client_hello_minimal_bytes
        )


class TestTlsHandshakeServerHello(unittest.TestCase):
    def setUp(self):
        self.server_hello_minimal_bytes = bytes(
            b'\x02'                             + # handshake_type = SERVER_HELLO
            b'\x00\x00\x28'                     + # length = 0x28
            b'\x03\x03'                         + # version = TLS1_2
            b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' + # time + random
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00'                             + # session_id_length
            b'\x00\x01'                         + # cipher_suite
            b'\x00'                             + # compression_method
            b'\x00\x00'                         + # extension_length
            b''
        )

        self.server_hello_minimal = TlsHandshakeServerHello(
            TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                datetime.datetime(2018, 8, 10, tzinfo=None),
                b'\x04\x05\x06\x07' + 
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x01\x02\x03\x04\x05\x06\x07',
            ),
            TlsSessionIdVector([]),
            TlsCompressionMethod.NULL,
            TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
            TlsExtensions([])
        )

    def test_parse(self):
        server_hello_minimal = TlsHandshakeServerHello.parse_exact_size(self.server_hello_minimal_bytes)

        self.assertEqual(
            server_hello_minimal.protocol_version,
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            server_hello_minimal.random,
            self.server_hello_minimal.random
        )
        self.assertEqual(
            server_hello_minimal.cipher_suite,
            self.server_hello_minimal.cipher_suite
        )
        self.assertEqual(
            server_hello_minimal.compression_method,
            self.server_hello_minimal.compression_method
        )
        self.assertEqual(
            server_hello_minimal.extensions,
            self.server_hello_minimal.extensions
        )

    def test_compose(self):
        self.assertEqual(
            self.server_hello_minimal.compose(),
            self.server_hello_minimal_bytes
        )


class TestTlsHandshakeCertificate(unittest.TestCase):
    def setUp(self):
        self.certificate_minimal_bytes = bytes(
            b'\x0b'                             + # handshake_type = CERTIFICATE
            b'\x00\x00\x31'                     + # length = 0x31
            b'\x00\x00\x2e'                     + # cretificates length = 0x2e
            b'\x00\x00\x10'                     + # cretificate length = 0x10
            b'peer certificate'                 + # certificate
            b'\x00\x00\x18'                     + # cretificate length = 0x18
            b'intermediate certificate'         + # certificate
            b''
        )

        self.certificate_minimal = TlsHandshakeCertificate(
            TlsCertificates([
                TlsCertificate(b'peer certificate'),
                TlsCertificate(b'intermediate certificate'),
            ])
        )

    def test_parse(self):
        certificate_minimal = TlsHandshakeCertificate.parse_exact_size(self.certificate_minimal_bytes)

        self.assertEqual(
            certificate_minimal.certificate_chain,
            self.certificate_minimal.certificate_chain
        )

    def test_compose(self):
        self.assertEqual(
            self.certificate_minimal.compose(),
            self.certificate_minimal_bytes
        )


class TestTlsHandshakeServerHelloDone(unittest.TestCase):
    def setUp(self):
        self.server_hello_done_bytes = bytes(
            b'\x0e'                             + # handshake_type = SERVER_HELLO_DONE
            b'\x00\x00\x00'                     + # length = 0x00
            b''
        )

        self.server_hello_done = TlsHandshakeServerHelloDone()

    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0x1 is not a valid TlsHandshakeServerHelloDone'):
            # pylint: disable=expression-not-assigned
            TlsHandshakeServerHelloDone.parse_exact_size(b'\x0e\x00\x00\x01\x00'),

    def test_parse(self):
        server_hello_done = TlsHandshakeServerHelloDone.parse_exact_size(self.server_hello_done_bytes)

    def test_compose(self):
        self.assertEqual(self.server_hello_done.compose(), self.server_hello_done_bytes)


class TestSslHandshakeClientHello(unittest.TestCase):
    def setUp(self):
        self.client_hello_bytes = bytes(
            b'\x00\x02'                         + # version = SSL2
            b'\x00\x06'                         + # cipher_kinds_length = 0x06
            b'\x00\x08'                         + # session_id_length = 0x08
            b'\x00\x10'                         + # challenge_length = 0x10
            b'\x01\x00\x80\x07\x00\xc0'         + # cipher_kinds
            b'\x00\x01\x02\x03\x04\x05\x06\x07' + # session_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' + # challenge
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
            b''
        )

        self.client_hello = SslHandshakeClientHello(
                cipher_kinds=[
                    SslCipherKind.RC4_128_WITH_MD5,
                    SslCipherKind.DES_192_EDE3_CBC_WITH_MD5
                ],
                session_id=b'\x00\x01\x02\x03\x04\x05\x06\x07',
                challenge=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )

    def test_parse(self):
        client_hello = SslHandshakeClientHello.parse_exact_size(self.client_hello_bytes)

    def test_compose(self):
        self.assertEqual(self.client_hello.compose(), self.client_hello_bytes)


class TestSslHandshakeServerHello(unittest.TestCase):
    def setUp(self):
        self.server_hello_bytes = bytes(
            b'\x00'                             + # session_id_hit = False
            b'\x01'                             + # certificate_type = X509_CERTIFICATE
            b'\x00\x02'                         + # version = SSL2
            b'\x00\x0b'                         + # certificate_length = 0x0b
            b'\x00\x06'                         + # cipher_kinds_length = 0x06
            b'\x00\x10'                         + # connection_id_length = 0x10
            b'certificate'                      + # certificate
            b'\x01\x00\x80\x07\x00\xc0'         + # cipher_kinds
            b'\x00\x01\x02\x03\x04\x05\x06\x07' + # connection_id
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
            b''
        )

        self.server_hello = SslHandshakeServerHello(
                certificate=b'certificate',
                cipher_kinds=[
                    SslCipherKind.RC4_128_WITH_MD5,
                    SslCipherKind.DES_192_EDE3_CBC_WITH_MD5
                ],
                connection_id=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
                session_id_hit=False
        )

    def test_parse(self):
        server_hello = SslHandshakeServerHello.parse_exact_size(self.server_hello_bytes)

    def test_compose(self):
        self.assertEqual(self.server_hello.compose(), self.server_hello_bytes)
