# -*- coding: utf-8 -*-

import unittest

import collections
import copy
import datetime

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.tls.algorithm import (
    TlsCipherSuiteExtension,
    TlsECPointFormat,
    TlsGreaseOneByte,
    TlsGreaseTwoByte,
    TlsNamedCurve,
    TlsSignatureAndHashAlgorithm,
)

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.extension import (
    TlsExtensionSupportedVersionsClient,
    TlsExtensionSupportedVersionsServer,
    TlsExtensionUnparsed,
    TlsExtensionEllipticCurves,
    TlsExtensionECPointFormats,
    TlsECPointFormatVector,
    TlsEllipticCurveVector,
    TlsSupportedVersionVector,
)
from cryptoparser.tls.grease import TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.subprotocol import (
    TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM,
    TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM_BYTES,
    SslHandshakeClientHello,
    SslHandshakeServerHello,
    SslMessageType,
    TlsAlertMessage,
    TlsCertificate,
    TlsCertificateStatusType,
    TlsCertificates,
    TlsClientCertificateType,
    TlsCipherSuiteVector,
    TlsCompressionMethod,
    TlsCompressionMethodVector,
    TlsContentType,
    TlsDistinguishedName,
    TlsExtensionType,
    TlsExtensionsClient,
    TlsExtensionsServer,
    TlsHandshakeCertificate,
    TlsHandshakeCertificateRequest,
    TlsHandshakeCertificateStatus,
    TlsHandshakeClientHello,
    TlsHandshakeHelloRandom,
    TlsHandshakeHelloRandomBytes,
    TlsHandshakeHelloRetryRequest,
    TlsHandshakeMessageVariant,
    TlsHandshakeServerHello,
    TlsHandshakeServerHelloDone,
    TlsHandshakeServerKeyExchange,
    TlsHandshakeType,
    TlsSessionIdVector,
    TlsSubprotocolMessageParser,
)

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from .classes import TestMessage


class TestSubprotocolParser(unittest.TestCase):
    def test_error(self):
        subprotocol_parser = TlsSubprotocolMessageParser(TlsContentType.HEARTBEAT)
        with self.assertRaises(InvalidValue) as context_manager:
            subprotocol_parser.parse(
                b'\x18' +      # type = heartbeat
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 1
                b'\x00'
            )
        self.assertEqual(context_manager.exception.value, 0x18)

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
            ('content_type', b'\x17'),
            ('data', b'\x00\x00\x00'),
        ])
        invalid_tls_message_bytes = b''.join(invalid_tls_message_dict.values())

        with self.assertRaisesRegex(InvalidValue, 'is not a valid TlsHandshakeMessageVariant'):
            TlsHandshakeMessageVariant.parse_exact_size(invalid_tls_message_bytes)

    def test_compose(self):
        self.assertEqual(TlsHandshakeMessageVariant(self.server_hello_done).compose(), self.server_hello_done_bytes)


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
            ('protocol_version', b'\x03\x01'),  # TLS1
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

        with self.assertRaises(NotEnoughData) as context_manager:
            TlsHandshakeClientHello.parse_exact_size(
                b'\x01'            # handshake_type: CLIENT_HELLO
                b'\x00\x00\x03' +  # handshake_length = 3
                b'\x03\x03' +      # version = TLS 1.2
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(InvalidValue) as context_manager:
            TlsHandshakeClientHello.parse_exact_size(
                b'\xff'            # handshake_type: INVALID
                b'\x00\x00\x02' +  # handshake_length = 2
                b'\x03\x03' +      # version = TLS 1.2
                b''
            )
        self.assertEqual(context_manager.exception.value, 0xff)

    def test_parse(self):
        record = TlsRecord.parse_exact_size(
            self.server_hello_done_record_bytes + self.server_hello_done_bytes
        )
        self.assertEqual(record.protocol_version, TlsProtocolVersion(TlsVersion.TLS1))
        record.protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        self.assertEqual(record.protocol_version, TlsProtocolVersion(TlsVersion.TLS1_2))


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

        self.random_time = datetime.datetime(2018, 8, 10, tzinfo=datetime.timezone.utc)
        self.client_hello_minimal = TlsHandshakeClientHello(
            TlsCipherSuiteVector([
                TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A),
                TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
                TlsCipherSuite.TLS_RSA_WITH_NULL_SHA,
                TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            ]),
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                self.random_time,
                TlsHandshakeHelloRandomBytes(bytearray(
                    b'\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b''
                ))
            ),
            TlsSessionIdVector(()),
            TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
            TlsExtensionsClient(()),
            fallback_scsv=True,
            empty_renegotiation_info_scsv=True,
        )

    def test_parse(self):
        client_hello_minimal = TlsHandshakeClientHello.parse_exact_size(self.client_hello_minimal_bytes)

        self.assertEqual(client_hello_minimal.get_handshake_type(), TlsHandshakeType.CLIENT_HELLO)

        self.assertEqual(
            client_hello_minimal.protocol_version,
            TlsProtocolVersion(TlsVersion.TLS1_2)
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
        self.assertEqual(len(client_hello_extension.extensions), 2)
        self.assertEqual(
            client_hello_extension.extensions.get_item_by_type(TlsExtensionType.SUPPORTED_VERSIONS),
            TlsExtensionSupportedVersionsClient(TlsSupportedVersionVector([
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]))
        )
        self.assertEqual(
            client_hello_extension.extensions[1],
            TlsExtensionUnparsed(TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A), b'')
        )
        with self.assertRaises(KeyError):
            client_hello_extension.extensions.get_item_by_type(TlsGreaseTwoByte.GREASE_0A0A)

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

    def test_ja3(self):
        client_hello_minimal = copy.copy(self.client_hello_minimal)
        self.assertEqual(client_hello_minimal.ja3(), '771,2570-1-2-3-4-5,,,')

        client_hello_minimal.extensions.append(
            TlsExtensionEllipticCurves(TlsEllipticCurveVector([TlsNamedCurve.SECT163K1]))
        )
        self.assertEqual(client_hello_minimal.ja3(), '771,2570-1-2-3-4-5,10,1,')
        client_hello_minimal.extensions[0].elliptic_curves.append(TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A))
        self.assertEqual(client_hello_minimal.ja3(), '771,2570-1-2-3-4-5,10,1,')

        client_hello_minimal.extensions.append(
            TlsExtensionECPointFormats(TlsECPointFormatVector([TlsECPointFormat.UNCOMPRESSED]))
        )
        self.assertEqual(client_hello_minimal.ja3(), '771,2570-1-2-3-4-5,10-11,1,0')
        client_hello_minimal.extensions[1].point_formats.append(TlsInvalidTypeOneByte(TlsGreaseOneByte.GREASE_0B))
        self.assertEqual(client_hello_minimal.ja3(), '771,2570-1-2-3-4-5,10-11,1,0')


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
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                datetime.datetime(2018, 8, 10, tzinfo=datetime.timezone.utc),
                TlsHandshakeHelloRandomBytes(bytearray(
                    b'\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b''
                ))
            ),
            TlsSessionIdVector(()),
            TlsCompressionMethod.NULL,
            TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
            TlsExtensionsServer(())
        )

        self.server_hello_minimal_bytes = b''.join(self.server_hello_minimal_dict.values())
        self.server_hello_minimal_extensions_dict = collections.OrderedDict([
            ('extensions_length', b'\x00\x0a'),
            ('extension_type', b'\x00\x2b'),  # SUPPORTED_VERSIONS
            ('extension_length', b'\x00\x05'),
            ('selected_version', b'\x03\x03'),  # TLS1_2
            ('extension_grease', b'\x0a\x0a'),
            ('extension_grease_length', b'\x00\x00'),
        ])
        self.server_hello_minimal_extensions_bytes = b''.join(self.server_hello_minimal_extensions_dict.values())
        self.server_hello_extension_bytes = bytearray(
            self.server_hello_minimal_bytes +
            self.server_hello_minimal_extensions_bytes +
            b''
        )
        self.server_hello_extension_bytes[3] += (
            len(self.server_hello_extension_bytes) -
            len(self.server_hello_minimal_bytes)
        )

    def test_parse(self):
        server_hello_minimal = TlsHandshakeServerHello.parse_exact_size(self.server_hello_minimal_bytes)

        self.assertEqual(server_hello_minimal.get_handshake_type(), TlsHandshakeType.SERVER_HELLO)

        self.assertEqual(
            server_hello_minimal.protocol_version,
            TlsProtocolVersion(TlsVersion.TLS1_2)
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

        server_hello_extension = TlsHandshakeServerHello.parse_exact_size(self.server_hello_extension_bytes)
        self.assertEqual(len(server_hello_extension.extensions), 2)
        self.assertEqual(
            server_hello_extension.extensions.get_item_by_type(TlsExtensionType.SUPPORTED_VERSIONS),
            TlsExtensionSupportedVersionsServer(TlsProtocolVersion(TlsVersion.TLS1_2))
        )
        self.assertEqual(
            server_hello_extension.extensions[1],
            TlsExtensionUnparsed(TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A), b'')
        )
        with self.assertRaises(KeyError):
            server_hello_extension.extensions.get_item_by_type(TlsGreaseTwoByte.GREASE_0A0A)

    def test_compose(self):
        self.assertEqual(
            self.server_hello_minimal.compose(),
            self.server_hello_minimal_bytes
        )


class TestTlsHandshakeHelloRetryRequest(unittest.TestCase):
    def setUp(self):
        self.hello_retry_request_minimal_dict = collections.OrderedDict([
            ('handshake_type', b'\x06'),              # HELLO_RETRY_REQUEST
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
        self.hello_retry_request_minimal_bytes = b''.join(self.hello_retry_request_minimal_dict.values())

        self.hello_retry_request_minimal = TlsHandshakeHelloRetryRequest(
            TlsCipherSuite.TLS_RSA_WITH_NULL_MD5,
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsHandshakeHelloRandom(
                datetime.datetime(2018, 8, 10, tzinfo=datetime.timezone.utc),
                TlsHandshakeHelloRandomBytes(bytearray(
                    b'\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                    b''
                ))
            ),
            TlsSessionIdVector(()),
            TlsCompressionMethod.NULL,
            TlsExtensionsClient(())
        )

    def test_parse(self):
        hello_retry_request_minimal = TlsHandshakeHelloRetryRequest.parse_exact_size(
            self.hello_retry_request_minimal_bytes
        )

        self.assertEqual(hello_retry_request_minimal.get_handshake_type(), TlsHandshakeType.HELLO_RETRY_REQUEST)

        self.assertEqual(
            hello_retry_request_minimal.protocol_version,
            TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            hello_retry_request_minimal.random_bytes,
            self.hello_retry_request_minimal.random_bytes
        )
        self.assertEqual(
            hello_retry_request_minimal.cipher_suite,
            self.hello_retry_request_minimal.cipher_suite
        )
        self.assertEqual(
            hello_retry_request_minimal.compression_method,
            self.hello_retry_request_minimal.compression_method
        )
        self.assertEqual(
            hello_retry_request_minimal.extensions,
            self.hello_retry_request_minimal.extensions
        )

    def test_compose(self):
        self.assertEqual(
            self.hello_retry_request_minimal.compose(),
            self.hello_retry_request_minimal_bytes
        )

    def test_random(self):
        self.assertEqual(
            TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM.compose(),
            TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM_BYTES
        )
        self.assertEqual(
            TlsHandshakeHelloRandom.parse_exact_size(TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM_BYTES),
            TLS_HANDSHAKE_HELLO_RETRY_REQUEST_RANDOM
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


class TestTlsHandshakeCertificateRequestTls10(unittest.TestCase):
    def setUp(self):
        self.certificate_request_dict = collections.OrderedDict([
            ('handshake_type', b'\x0d'),                  # CERTIFICATE_REQUEST
            ('length', b'\x00\x00\x19'),
            ('certificate_types_length', b'\x04'),
            ('certificate_types', b'\x01\02\x03\x04'),
            ('certificate_authorities_length', b'\x00\x12'),
            ('certificate_authority_length', b'\x00\x10'),
            ('certificate_authority', b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        self.certificate_request_bytes = b''.join(self.certificate_request_dict.values())

        self.certificate_request = TlsHandshakeCertificateRequest(
            certificate_types=[
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.RSA_FIXED_DH,
                TlsClientCertificateType.DSS_FIXED_DH,
            ],
            certificate_authorities=[
                TlsDistinguishedName(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
            ]
        )

    def test_parse(self):
        certificate_request = TlsHandshakeCertificateRequest.parse_exact_size(self.certificate_request_bytes)

        self.assertEqual(
            list(certificate_request.certificate_types),
            [
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.RSA_FIXED_DH,
                TlsClientCertificateType.DSS_FIXED_DH,
            ]
        )
        self.assertEqual(
            list(certificate_request.certificate_authorities),
            [TlsDistinguishedName(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'), ]
        )
        self.assertEqual(certificate_request.supported_signature_algorithms, None)

    def test_compose(self):
        self.assertEqual(
            self.certificate_request.compose(),
            self.certificate_request_bytes
        )


class TestTlsHandshakeCertificateRequestTls12(unittest.TestCase):
    def setUp(self):
        self.certificate_request_dict = collections.OrderedDict([
            ('handshake_type', b'\x0d'),                  # CERTIFICATE_REQUEST
            ('length', b'\x00\x00\x23'),
            ('certificate_types_length', b'\x04'),
            ('certificate_types', b'\x01\02\x03\x04'),
            ('signature_algorithm_list_length', b'\x00\x08'),
            ('signature_algorithm_list', b'\x01\x00\x02\x01\x03\x02\x04\x03'),
            ('certificate_authorities_length', b'\x00\x12'),
            ('certificate_authority_length', b'\x00\x10'),
            ('certificate_authority', b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        self.certificate_request_bytes = b''.join(self.certificate_request_dict.values())

        self.certificate_request = TlsHandshakeCertificateRequest(
            certificate_types=[
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.RSA_FIXED_DH,
                TlsClientCertificateType.DSS_FIXED_DH,
            ],
            supported_signature_algorithms=[
                TlsSignatureAndHashAlgorithm.ANONYMOUS_MD5,
                TlsSignatureAndHashAlgorithm.RSA_SHA1,
                TlsSignatureAndHashAlgorithm.DSA_SHA224,
                TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            ],
            certificate_authorities=[
                TlsDistinguishedName(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
            ]
        )

    def test_parse(self):
        certificate_request = TlsHandshakeCertificateRequest.parse_exact_size(self.certificate_request_bytes)

        self.assertEqual(
            list(certificate_request.certificate_types),
            [
                TlsClientCertificateType.RSA_SIGN,
                TlsClientCertificateType.DSS_SIGN,
                TlsClientCertificateType.RSA_FIXED_DH,
                TlsClientCertificateType.DSS_FIXED_DH,
            ]
        )
        self.assertEqual(
            list(certificate_request.supported_signature_algorithms),
            [
                TlsSignatureAndHashAlgorithm.ANONYMOUS_MD5,
                TlsSignatureAndHashAlgorithm.RSA_SHA1,
                TlsSignatureAndHashAlgorithm.DSA_SHA224,
                TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            ]
        )
        self.assertEqual(
            list(certificate_request.certificate_authorities),
            [TlsDistinguishedName(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'), ]
        )

    def test_compose(self):
        self.assertEqual(
            self.certificate_request.compose(),
            self.certificate_request_bytes
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
        error_regex = 'b\'\\\\x00\' is not a valid TlsHandshakeServerHelloDone payload value'
        with self.assertRaisesRegex(InvalidValue, error_regex):
            # pylint: disable=expression-not-assigned
            TlsHandshakeServerHelloDone.parse_exact_size(b'\x0e\x00\x00\x01\x00')

    def test_parse(self):
        server_hello_done = TlsHandshakeServerHelloDone.parse_exact_size(self.server_hello_done_bytes)

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

        self.assertEqual(server_key_exchange.get_handshake_type(), TlsHandshakeType.SERVER_KEY_EXCHANGE)

        self.assertEqual(server_key_exchange.param_bytes, self.param_bytes)

    def test_compose(self):
        self.assertEqual(self.server_key_exchange.compose(), self.server_key_exchange_bytes)


class TestTlsHandshakeCertificateStatus(unittest.TestCase):
    def setUp(self):
        self.status_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        self.certificate_status_bytes = bytes(
            b'\x16' +                              # handshake_type = CERTIFICATE_STATUS
            b'\x00\x00\x0c' +                      # length = 0x0c
            b'\x01' +                              # status_type = OCSP
            b'\x00\x00\x08' +                      # length = 0x08
            self.status_bytes +                    # status_bytes
            b''
        )

        self.certificate_status = TlsHandshakeCertificateStatus(TlsCertificateStatusType.OCSP, self.status_bytes)

    def test_parse(self):
        certificate_status = TlsHandshakeCertificateStatus.parse_exact_size(self.certificate_status_bytes)

        self.assertEqual(certificate_status.get_handshake_type(), TlsHandshakeType.CERTIFICATE_STATUS)

        self.assertEqual(certificate_status.status, self.status_bytes)

    def test_compose(self):
        self.assertEqual(self.certificate_status.compose(), self.certificate_status_bytes)


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
                SslCipherKind.SSL_CK_RC4_128_WITH_MD5,
                SslCipherKind.SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            ],
            session_id=b'\x00\x01\x02\x03\x04\x05\x06\x07',
            challenge=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )

    def test_default(self):
        self.assertEqual(SslHandshakeClientHello([]).session_id, b'')
        self.assertNotEqual(SslHandshakeClientHello([]).challenge, SslHandshakeClientHello([]).challenge)

        self.assertEqual(SslHandshakeServerHello(b'', []).connection_id, b'')

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
                SslCipherKind.SSL_CK_RC4_128_WITH_MD5,
                SslCipherKind.SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            ],
            connection_id=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            session_id_hit=False
        )

    def test_parse(self):
        server_hello_minimal = SslHandshakeServerHello.parse_exact_size(self.server_hello_bytes)

        self.assertEqual(server_hello_minimal.get_message_type(), SslMessageType.SERVER_HELLO)

    def test_compose(self):
        self.assertEqual(self.server_hello.compose(), self.server_hello_bytes)
