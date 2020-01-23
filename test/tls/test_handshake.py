# -*- coding: utf-8 -*-

import unittest

import collections
import datetime
import six

from cryptoparser.common.exception import InvalidValue, InvalidType, NotEnoughData

from cryptoparser.tls.ciphersuite import TlsCipherSuite, TlsCipherSuiteExtension, SslCipherKind
from cryptoparser.tls.extension import TlsExtensionSupportedVersions, TlsExtensionUnparsed
from cryptoparser.tls.grease import TlsGreaseTwoByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.subprotocol import TlsSubprotocolMessageParser, TlsHandshakeMessageVariant
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsHandshakeServerHello, TlsHandshakeHelloRandom
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsCompressionMethodVector, TlsCompressionMethod
from cryptoparser.tls.subprotocol import TlsSessionIdVector, TlsExtensions, TlsContentType, TlsHandshakeType
from cryptoparser.tls.subprotocol import TlsHandshakeCertificate, TlsCertificates, TlsCertificate
from cryptoparser.tls.subprotocol import TlsHandshakeServerHelloDone, TlsHandshakeServerKeyExchange, TlsAlertMessage
from cryptoparser.tls.subprotocol import SslMessageType, SslHandshakeClientHello, SslHandshakeServerHello
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from .classes import TestMessage, TestVariantMessage


class TestSubprotocolParser(unittest.TestCase):
    def test_registered_parser(self):
        tls_message_dict = collections.OrderedDict([
            ('level', b'\x02'),        # FATAL
            ('description', b'\x28'),  # HANDSHAKE_FAILURE
        ])
        tls_message_bytes = b''.join(tls_message_dict.values())
        tls_parser = TlsSubprotocolMessageParser(TlsContentType.ALERT)
        tls_parser.parse(tls_message_bytes)

        tls_parser.register_subprotocol_parser(TlsContentType.ALERT, TestMessage)
        with self.assertRaises(NotImplementedError):
            tls_parser.parse(tls_message_bytes)

        tls_parser.register_subprotocol_parser(TlsContentType.ALERT, TlsAlertMessage)
        parsed_object, _ = tls_parser.parse(tls_message_bytes)
        self.assertEqual(parsed_object.compose(), tls_message_bytes)


class TestVariantParsable(unittest.TestCase):
    def setUp(self):
        self.server_hello_done_dict = collections.OrderedDict([
            ('handshake_type', b'\x0e'),  # SERVER_HELLO_DONE
            ('length', b'\x00\x00\x00'),  # 0x00
        ])
        self.server_hello_done_bytes = b''.join(self.server_hello_done_dict.values())
        self.server_hello_done = TlsHandshakeServerHelloDone()

    def test_error(self):
        invalid_tls_message_dict = collections.OrderedDict([
            ('type', b'\x16'),         # HANDSHAKE
            ('version', b'\x03\x01'),  # TLS1_0
            ('length', b'\x00\x01'),
            ('invalid_data', b'\xff'),
        ])
        invalid_tls_message_bytes = b''.join(invalid_tls_message_dict.values())

        with six.assertRaisesRegex(self, InvalidValue, 'is not a valid TlsHandshakeMessageVariant'):
            TlsHandshakeMessageVariant.parse_exact_size(invalid_tls_message_bytes)

    def test_compose(self):
        self.assertEqual(TlsHandshakeMessageVariant(self.server_hello_done).compose(), self.server_hello_done_bytes)

    def test_registered_parser(self):
        message = TlsHandshakeMessageVariant.parse_exact_size(self.server_hello_done_bytes)
        self.assertEqual(message.compose(), self.server_hello_done_bytes)

        TlsHandshakeMessageVariant.register_variant_parser(TlsHandshakeType.SERVER_HELLO_DONE, TestVariantMessage)
        with self.assertRaises(NotImplementedError):
            TlsHandshakeMessageVariant.parse_exact_size(self.server_hello_done_bytes)

        TlsHandshakeMessageVariant.register_variant_parser(
            TlsHandshakeType.SERVER_HELLO_DONE,
            TlsHandshakeServerHelloDone
        )
        parsed_object = TlsHandshakeMessageVariant.parse_exact_size(self.server_hello_done_bytes)
        self.assertEqual(parsed_object.compose(), self.server_hello_done_bytes)
        self.assertEqual(parsed_object.get_content_type(), TlsContentType.HANDSHAKE)
        self.assertEqual(parsed_object.get_handshake_type(), TlsHandshakeType.SERVER_HELLO_DONE)


class TestTlsCipherSuiteVector(unittest.TestCase):
    def test_parse(self):
        cipher_suites = TlsCipherSuiteVector.parse_exact_size(b'\x00\x02\x00\x00')
        self.assertEqual(cipher_suites, TlsCipherSuiteVector([TlsCipherSuite.TLS_NULL_WITH_NULL_NULL]))

        cipher_suites = TlsCipherSuiteVector.parse_exact_size(b'\x00\x04\x56\x00\x00\xff')
        self.assertEqual(
            cipher_suites,
            TlsCipherSuiteVector([
                TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.FALLBACK_SCSV),
                TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.EMPTY_RENEGOTIATION_INFO_SCSV),
            ])
        )

        cipher_suites = TlsCipherSuiteVector.parse_exact_size(b'\x00\x06\x56\x00\x00\x00\x00\xff')
        self.assertEqual(
            cipher_suites,
            TlsCipherSuiteVector([
                TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.FALLBACK_SCSV),
                TlsCipherSuite.TLS_NULL_WITH_NULL_NULL,
                TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.EMPTY_RENEGOTIATION_INFO_SCSV),
            ])
        )


class TestTlsHandshake(unittest.TestCase):
    def setUp(self):
        self.server_hello_done_dict = collections.OrderedDict([
            ('handshake_type', b'\x0e'),  # SERVER_HELLO_DONE
            ('length', b'\x00\x00\x00'),
        ])
        self.server_hello_done_bytes = b''.join(self.server_hello_done_dict.values())
        self.server_hello_done_record_dict = collections.OrderedDict([
            ('content_type', b'\x16'),          # HANDSHAKE
            ('protocol_version', b'\x03\x01'),  # TLS1_0
            ('length', b'\x00\x04'),
        ])
        self.server_hello_done_record_bytes = b''.join(self.server_hello_done_record_dict.values())

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
        self.client_hello_minimal_dict = collections.OrderedDict([
            ('handshake_type ', b'\x01'),  # CLIENT_HELLO
            ('length ', b'\x00\x00\x37'),
            ('version ', b'\x03\x03'),
            ('random ',
             b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b''),
            ('session_id_length', b'\x00'),
            ('cipher_suite_length', b'\x00\x10'),
            ('cipher_suites',
             b'\x0a\x0a\x00\x01\x00\x02\x00\x03' +
             b'\x00\x04\x00\x05\x56\x00\x00\xff' +
             b''),
            ('compression_method_length', b'\x01'),
            ('compression_methods', b'\x00'),
        ])
        self.client_hello_minimal_bytes = b''.join(self.client_hello_minimal_dict.values())
        self.client_hello_minimal_extensions_dict = collections.OrderedDict([
            ('extensions_length', b'\x00\x0d'),
            ('extension_type', b'\x00\x2b'),  # SUPPORTED_VERSIONS
            ('extension_length', b'\x00\x05'),
            ('supported_version_list_length', b'\x04'),
            ('supported_version_list', b'\x03\x02\x03\x03'),  # TLS1_1, TLS1_2
            ('extension_grease', b'\x0a\x0a'),
            ('extension_grease_length', b'\x00\x00'),
        ])
        self.client_hello_minimal_extensions_bytes = b''.join(self.client_hello_minimal_extensions_dict.values())
        self.client_hello_extension_bytes = bytearray(
            self.client_hello_minimal_bytes +
            self.client_hello_minimal_extensions_bytes +
            b''
        )
        self.client_hello_extension_bytes[3] += (
            len(self.client_hello_extension_bytes) -
            len(self.client_hello_minimal_bytes)
        )

        self.random_time = datetime.datetime(2018, 8, 10, tzinfo=None)
        self.client_hello_minimal = TlsHandshakeClientHello(
            TlsCipherSuiteVector([
                TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A),
                TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
                TlsCipherSuite.TLS_RSA_WITH_NULL_SHA,
                TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
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
            fallback_scsv=True,
            empty_renegotiation_info_scsv=True,
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
        self.assertTrue(client_hello_minimal.fallback_scsv)
        self.assertTrue(client_hello_minimal.empty_renegotiation_info_scsv)

        client_hello_extension = TlsHandshakeClientHello.parse_exact_size(self.client_hello_extension_bytes)
        print(client_hello_extension.extensions)
        self.assertEqual(
            client_hello_extension.extensions,
            TlsExtensions([
                TlsExtensionSupportedVersions([
                    TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                    TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                ]),
                TlsExtensionUnparsed(TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A), b'')
            ])
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
        self.server_hello_minimal_dict = collections.OrderedDict([
            ('handshake_type', b'\x02'),              # SERVER_HELLO
            ('length', b'\x00\x00\x26'),
            ('version', b'\x03\x03'),                 # TLS1_2
            ('random',
             b'\x5b\x6c\xd5\x80\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b''),
            ('session_id_length', b'\x00'),
            ('cipher_suite', b'\x00\x01'),
            ('compression_method', b'\x00'),
        ])
        self.server_hello_minimal_bytes = b''.join(self.server_hello_minimal_dict.values())

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
        self.certificate_minimal_dict = collections.OrderedDict([
            ('handshake_type', b'\x0b'),                  # CERTIFICATE
            ('length', b'\x00\x00\x31'),
            ('cretificates', b'\x00\x00\x2e'),
            ('peer_cretificate_length', b'\x00\x00\x10'),
            ('peer_certificate_bytes', b'peer certificate'),
            ('intermrdiate_cretificate_length', b'\x00\x00\x18'),
            ('intermrdiate_certificate_bytes', b'intermediate certificate'),
        ])
        self.certificate_minimal_bytes = b''.join(self.certificate_minimal_dict.values())

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
        self.server_hello_done_dict = collections.OrderedDict([
            ('handshake_type', b'\x0e'),  # SERVER_HELLO_DONE
            ('length', b'\x00\x00\x00'),  # 0x00
        ])
        self.server_hello_done_bytes = b''.join(self.server_hello_done_dict.values())

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
        self.server_key_exchange_dict = collections.OrderedDict([
            ('handshake_type', b'\x0c'),       # SERVER_KEY_EXCHANGE
            ('length', b'\x00\x00\x08'),
            ('param_bytes', self.param_bytes),
        ])
        self.server_key_exchange_bytes = b''.join(self.server_key_exchange_dict.values())

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
        self.client_hello_dict = collections.OrderedDict([
            ('version', b'\x00\x02'),                              # SSL2
            ('cipher_kinds_length', b'\x00\x06'),
            ('session_id_length', b'\x00\x08'),
            ('challenge_length', b'\x00\x10'),
            ('cipher_kinds', b'\x01\x00\x80\x07\x00\xc0'),
            ('session_id', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('challenge',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
             b'')
        ])
        self.client_hello_bytes = b''.join(self.client_hello_dict.values())

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
        self.server_hello_done_dict = collections.OrderedDict([
            ('session_id_hit', b'\x00'),                    # False
            ('certificate_type', b'\x01'),                  # X509_CERTIFICATE
            ('version', b'\x00\x02'),                       # SSL2
            ('certificate_length', b'\x00\x0b'),
            ('cipher_kinds_length', b'\x00\x06'),
            ('connection_id_length', b'\x00\x10'),
            ('certificate', b'certificate'),
            ('cipher_kinds', b'\x01\x00\x80\x07\x00\xc0'),
            ('connection_id',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
             b''),
        ])
        self.server_hello_bytes = b''.join(self.server_hello_done_dict.values())

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
