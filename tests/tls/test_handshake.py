#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import datetime
import six

from cryptoparser.common.exception import InvalidValue, InvalidType, NotEnoughData

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.extension import TlsExtensionSupportedVersions
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsHandshakeServerHello, TlsHandshakeHelloRandom
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsCompressionMethodVector, TlsCompressionMethod
from cryptoparser.tls.subprotocol import TlsSessionIdVector, TlsExtensions, TlsContentType, TlsHandshakeType
from cryptoparser.tls.subprotocol import TlsHandshakeCertificate, TlsCertificates, TlsCertificate
from cryptoparser.tls.subprotocol import TlsHandshakeServerHelloDone, TlsHandshakeServerKeyExchange
from cryptoparser.tls.subprotocol import SslMessageType, SslHandshakeClientHello, SslHandshakeServerHello
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal


class TestTlsHandshake(unittest.TestCase):
    def setUp(self):
        self.server_hello_done_bytes = bytes(
            b'\x0e' +                              # handshake_type = SERVER_HELLO_DONE
            b'\x00\x00\x00' +                      # length = 0x00
            b''
        )
        self.server_hello_done_record_bytes = bytes(
            b'\x16' +                              # content_type = HANDSHAKE
            b'\x03\x01' +                          # protocol_version = TLS1_0
            b'\x00\x04' +                          # length = 0x04
            b''
        )

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsHandshakeClientHello.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 4)

        with self.assertRaises(InvalidType):
            # pylint: disable=expression-not-assigned
            TlsHandshakeClientHello.parse_exact_size(self.server_hello_done_bytes)

    def test_parse(self):
        record = TlsRecord.parse_exact_size(
            self.server_hello_done_record_bytes + self.server_hello_done_bytes
        )
        self.assertEqual(record.protocol_version, TlsProtocolVersionFinal(TlsVersion.TLS1_0))
        record.protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        self.assertEqual(record.protocol_version, TlsProtocolVersionFinal(TlsVersion.TLS1_2))


class TestTlsHandshakeClientHello(unittest.TestCase):
    def setUp(self):
        self.client_hello_minimal_bytes = bytearray(
            b'\x01' +                              # handshake_type = CLIENT_HELLO
            b'\x00\x00\x37' +                      # length = 0x37
            b'\x03\x03' +                          # version = TLS1_2
            b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' +  # time + random
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00' +                              # session_id_length
            b'\x00\x10' +                          # cipher_suite_length
            b'\x00\x00\x00\x01\x00\x02\x00\x03' +  # cipher_suites
            b'\x00\x04\x00\x05\x00\x06\x00\x07' +
            b'\x01' +                              # compression_method_length
            b'\x00' +                              # compression_methods
            b''
        )
        self.client_hello_extension_bytes = bytearray(
            self.client_hello_minimal_bytes +
            b'\x00\x09' +                          # extensions_length = 9
            b'\x00\x2b' +                          # extension_type = SUPPORTED_VERSIONS
            b'\x00\x05' +                          # extension_length = 5
            b'\x04' +                              # supported_version_list_length = 4
            b'\x03\x02\x03\x03' +                  # supported_version_list
            b''
        )
        self.client_hello_extension_bytes[3] += (
            len(self.client_hello_extension_bytes) -
            len(self.client_hello_minimal_bytes)
        )

        self.random_time = datetime.datetime(2018, 8, 10, tzinfo=None)
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
                self.random_time,
                bytearray(
                    b'\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b''
                )
            ),
            TlsSessionIdVector(()),
            TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
            TlsExtensions(()),
        )

    def test_parse(self):
        client_hello_minimal = TlsHandshakeClientHello.parse_exact_size(self.client_hello_minimal_bytes)

        self.assertEqual(client_hello_minimal.get_content_type(), TlsContentType.HANDSHAKE)
        self.assertEqual(client_hello_minimal.get_handshake_type(), TlsHandshakeType.CLIENT_HELLO)

        self.assertEqual(
            client_hello_minimal.protocol_version,
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            client_hello_minimal.random,
            self.client_hello_minimal.random
        )
        self.assertEqual(
            client_hello_minimal.random.time,
            self.random_time,
        )
        self.assertEqual(
            client_hello_minimal.random.random,
            self.client_hello_minimal.random.random
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

        client_hello_extension = TlsHandshakeClientHello.parse_exact_size(self.client_hello_extension_bytes)
        self.assertEqual(
            client_hello_extension.extensions,
            TlsExtensions([TlsExtensionSupportedVersions([
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ])])
        )

    def test_compose(self):
        self.assertEqual(
            self.client_hello_minimal.compose(),
            self.client_hello_minimal_bytes
        )
        client_hello_extension = TlsHandshakeClientHello.parse_exact_size(self.client_hello_extension_bytes)
        self.assertEqual(
            client_hello_extension.compose(),
            self.client_hello_extension_bytes
        )


class TestTlsHandshakeServerHello(unittest.TestCase):
    def setUp(self):
        self.server_hello_minimal_bytes = bytearray(
            b'\x02' +                              # handshake_type = SERVER_HELLO
            b'\x00\x00\x26' +                      # length = 0x28
            b'\x03\x03' +                          # version = TLS1_2
            b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' +  # time + random
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00' +                              # session_id_length
            b'\x00\x01' +                          # cipher_suite
            b'\x00' +                              # compression_method
            b''
        )

        self.server_hello_minimal = TlsHandshakeServerHello(
            TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                datetime.datetime(2018, 8, 10, tzinfo=None),
                bytearray(
                    b'\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b''
                )
            ),
            TlsSessionIdVector(()),
            TlsCompressionMethod.NULL,
            TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
            TlsExtensions(())
        )

    def test_parse(self):
        server_hello_minimal = TlsHandshakeServerHello.parse_exact_size(self.server_hello_minimal_bytes)

        self.assertEqual(server_hello_minimal.get_content_type(), TlsContentType.HANDSHAKE)
        self.assertEqual(server_hello_minimal.get_handshake_type(), TlsHandshakeType.SERVER_HELLO)

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
        self.certificate_minimal_bytes = bytearray(
            b'\x0b' +                              # handshake_type = CERTIFICATE
            b'\x00\x00\x31' +                      # length = 0x31
            b'\x00\x00\x2e' +                      # cretificates length = 0x2e
            b'\x00\x00\x10' +                      # cretificate length = 0x10
            b'peer certificate' +                  # certificate
            b'\x00\x00\x18' +                      # cretificate length = 0x18
            b'intermediate certificate' +          # certificate
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
        self.server_hello_done_bytes = bytearray(
            b'\x0e' +                              # handshake_type = SERVER_HELLO_DONE
            b'\x00\x00\x00' +                      # length = 0x00
            b''
        )

        self.server_hello_done = TlsHandshakeServerHelloDone()

    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0x1 is not a valid TlsHandshakeServerHelloDone'):
            # pylint: disable=expression-not-assigned
            TlsHandshakeServerHelloDone.parse_exact_size(b'\x0e\x00\x00\x01\x00'),

    def test_parse(self):
        server_hello_done = TlsHandshakeServerHelloDone.parse_exact_size(self.server_hello_done_bytes)

        self.assertEqual(server_hello_done.get_content_type(), TlsContentType.HANDSHAKE)
        self.assertEqual(server_hello_done.get_handshake_type(), TlsHandshakeType.SERVER_HELLO_DONE)

    def test_compose(self):
        self.assertEqual(self.server_hello_done.compose(), self.server_hello_done_bytes)


class TestTlsHandshakeServerKeyExcahnge(unittest.TestCase):
    def setUp(self):
        self.param_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        self.server_key_exchange_bytes = bytes(
            b'\x0c' +                              # handshake_type = SERVER_KEY_EXCHANGE
            b'\x00\x00\x08' +                      # length = 0x00
            self.param_bytes +                     # param_bytes
            b''
        )

        self.server_key_exchange = TlsHandshakeServerKeyExchange(self.param_bytes)

    def test_parse(self):
        server_key_exchange = TlsHandshakeServerKeyExchange.parse_exact_size(self.server_key_exchange_bytes)

        self.assertEqual(server_key_exchange.get_content_type(), TlsContentType.HANDSHAKE)
        self.assertEqual(server_key_exchange.get_handshake_type(), TlsHandshakeType.SERVER_KEY_EXCHANGE)

        self.assertEqual(server_key_exchange.param_bytes, self.param_bytes)

    def test_compose(self):
        self.assertEqual(self.server_key_exchange.compose(), self.server_key_exchange_bytes)


class TestSslHandshakeClientHello(unittest.TestCase):
    def setUp(self):
        self.client_hello_bytes = bytearray(
            b'\x00\x02' +                          # version = SSL2
            b'\x00\x06' +                          # cipher_kinds_length = 0x06
            b'\x00\x08' +                          # session_id_length = 0x08
            b'\x00\x10' +                          # challenge_length = 0x10
            b'\x01\x00\x80\x07\x00\xc0' +          # cipher_kinds
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +  # session_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +  # challenge
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
        client_hello_minimal = SslHandshakeClientHello.parse_exact_size(self.client_hello_bytes)

        self.assertEqual(client_hello_minimal.get_message_type(), SslMessageType.CLIENT_HELLO)

    def test_compose(self):
        self.assertEqual(self.client_hello.compose(), self.client_hello_bytes)


class TestSslHandshakeServerHello(unittest.TestCase):
    def setUp(self):
        self.server_hello_bytes = bytearray(
            b'\x00' +                              # session_id_hit = False
            b'\x01' +                              # certificate_type = X509_CERTIFICATE
            b'\x00\x02' +                          # version = SSL2
            b'\x00\x0b' +                          # certificate_length = 0x0b
            b'\x00\x06' +                          # cipher_kinds_length = 0x06
            b'\x00\x10' +                          # connection_id_length = 0x10
            b'certificate' +                       # certificate
            b'\x01\x00\x80\x07\x00\xc0' +          # cipher_kinds
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +  # connection_id
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
        server_hello_minimal = SslHandshakeServerHello.parse_exact_size(self.server_hello_bytes)

        self.assertEqual(server_hello_minimal.get_message_type(), SslMessageType.SERVER_HELLO)

    def test_compose(self):
        self.assertEqual(self.server_hello.compose(), self.server_hello_bytes)
