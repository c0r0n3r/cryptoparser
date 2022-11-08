# -*- coding: utf-8 -*-

import collections
import unittest

import six

from cryptoparser.common.exception import NotEnoughData, InvalidType, InvalidValue
from cryptoparser.common.x509 import SerializedSCT
from cryptoparser.tls.algorithm import (
    TlsECPointFormat,
    TlsNamedCurve,
    TlsNextProtocolName,
    TlsProtocolName,
    TlsSignatureAndHashAlgorithm,
)
from cryptoparser.tls.extension import (
    TlsCertificateStatusRequestExtensions,
    TlsCertificateStatusRequestResponderId,
    TlsCertificateStatusRequestResponderIdList,
    TlsExtensionApplicationLayerProtocolNegotiation,
    TlsExtensionApplicationLayerProtocolSettings,
    TlsExtensionCertificateStatusRequest,
    TlsExtensionECPointFormats,
    TlsExtensionEllipticCurves,
    TlsExtensionEncryptThenMAC,
    TlsExtensionExtendedMasterSecret,
    TlsExtensionKeyShareClient,
    TlsExtensionKeyShareClientHelloRetry,
    TlsExtensionKeyShareServer,
    TlsExtensionKeyShareReservedClient,
    TlsExtensionNextProtocolNegotiationClient,
    TlsExtensionNextProtocolNegotiationServer,
    TlsExtensionPskKeyExchangeModes,
    TlsExtensionRecordSizeLimit,
    TlsExtensionRenegotiationInfo,
    TlsExtensionServerName,
    TlsExtensionSessionTicket,
    TlsExtensionSignatureAlgorithms,
    TlsExtensionSignatureAlgorithmsCert,
    TlsExtensionSignedCertificateTimestamp,
    TlsExtensionSupportedVersionsClient,
    TlsExtensionSupportedVersionsServer,
    TlsExtensionTokenBinding,
    TlsExtensionUnparsed,
    TlsExtensionParsed,
    TlsExtensionType,
    TlsNextProtocolNameList,
    TlsProtocolNameList,
    TlsPskKeyExchangeMode,
    TlsRenegotiatedConnection,
    TlsTokenBindingParamater,
    TlsTokenBindingProtocolVersion,
)
from cryptoparser.tls.grease import TlsGreaseOneByte, TlsGreaseTwoByte, TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, TlsProtocolVersionDraft

from .classes import TestUnusedDataExtension


class TestExtensionUnparsed(unittest.TestCase):

    def test_error(self):
        extension_missing_data_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x01'),
        ])
        extension_missing_data_bytes = b''.join(extension_missing_data_dict.values())
        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsExtensionUnparsed.parse_exact_size(extension_missing_data_bytes)
        self.assertEqual(context_manager.exception.bytes_needed, 5)

    def test_parse_and_compose(self):
        extension_minimal_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_minimal_bytes = b''.join(extension_minimal_dict.values())

        extension_minimal = TlsExtensionUnparsed.parse_exact_size(extension_minimal_bytes)
        self.assertEqual(extension_minimal.compose(), extension_minimal_bytes)

        extension_with_data_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x04'),
            ('extension_data', b'\xde\xad\xbe\xaf'),
        ])
        extension_with_data_bytes = b''.join(extension_with_data_dict.values())

        extension_with_data = TlsExtensionUnparsed.parse_exact_size(extension_with_data_bytes)
        self.assertEqual(extension_with_data.compose(), extension_with_data_bytes)


class ExtensionInvalidType(TlsExtensionParsed):
    @classmethod
    def get_extension_type(cls):
        return 0xffff

    @classmethod
    def _parse(cls, parsable):
        parser = super(ExtensionInvalidType, cls)._parse_header(parsable)

        return ExtensionInvalidType(), parser.parsed_length

    def compose(self):
        raise NotImplementedError


class TestExtensionParsed(unittest.TestCase):
    def test_error(self):
        extension_invalid_type_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_invalid_type_bytes = b''.join(extension_invalid_type_dict.values())

        with self.assertRaises(InvalidType):
            # pylint: disable=expression-not-assigned
            ExtensionInvalidType.parse_exact_size(extension_invalid_type_bytes)


class TestExtensionHostname(unittest.TestCase):
    def test_parse(self):
        extension_hostname_empty_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_hostname_empty_bytes = b''.join(extension_hostname_empty_dict.values())

        extension_hostname_empty = TlsExtensionServerName.parse_exact_size(extension_hostname_empty_bytes)
        self.assertEqual(extension_hostname_empty.host_name, '')
        self.assertEqual(extension_hostname_empty.compose(), extension_hostname_empty_bytes)

        extension_hostname_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x14'),
            ('name_list_length', b'\x00\x12'),
            ('name_type', b'\x00'),
            ('name_length', b'\x00\x0f'),
            ('name', b'\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d')
        ])
        extension_hostname_bytes = b''.join(extension_hostname_dict.values())

        extension_hostname = TlsExtensionServerName.parse_exact_size(extension_hostname_bytes)
        self.assertEqual(extension_hostname.host_name, 'www.example.com')
        self.assertEqual(extension_hostname.compose(), extension_hostname_bytes)

        extension_hostname_internationalized_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x1e'),
            ('name_list_length', b'\x00\x1c'),
            ('name_type', b'\x00'),
            ('name_length', b'\x00\x19'),
            (
                'name',
                b'\x78\x6e\x2d\x2d\x73\x6c\x61\x6e\x64\x2d\x79\x73\x61\x2e\x69\x63\x6f\x6d\x2e\x6d\x75\x73\x65\x75\x6d'
            )
        ])
        extension_hostname_internationalized_bytes = b''.join(extension_hostname_internationalized_dict.values())

        extension_hostname_internationalized = TlsExtensionServerName.parse_exact_size(
            extension_hostname_internationalized_bytes
        )
        self.assertEqual(extension_hostname_internationalized.host_name, six.ensure_text('ísland.icom.museum'))
        self.assertEqual(extension_hostname_internationalized.compose(), extension_hostname_internationalized_bytes)


class TestExtensionECPointFormat(unittest.TestCase):
    def test_parse(self):
        extension_ec_point_formats_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0b'),
            ('extension_length', b'\x00\x03'),
            ('ec_point_format_list_length', b'\x02'),
            ('ec_point_format_list', b'\x00\x0b'),
        ])
        extension_ec_point_formats_bytes = b''.join(extension_ec_point_formats_dict.values())

        extension_point_formats = TlsExtensionECPointFormats.parse_exact_size(extension_ec_point_formats_bytes)
        self.assertEqual(
            list(extension_point_formats.point_formats),
            [
                TlsECPointFormat.UNCOMPRESSED,
                TlsInvalidTypeOneByte(TlsGreaseOneByte.GREASE_0B),
            ]
        )
        self.assertEqual(extension_point_formats.compose(), extension_ec_point_formats_bytes)


class TestExtensionEllipticCurves(unittest.TestCase):
    def test_parse(self):
        extension_elliptic_curves_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0a'),
            ('extension_length', b'\x00\x0a'),
            ('elliptic_curve_list_length', b'\x00\x08'),
            ('elliptic_curve_list', b'\x00\x1d\x00\x17\x00\x18\x0a\x0a'),
        ])
        extension_elliptic_curves_bytes = b''.join(extension_elliptic_curves_dict.values())

        extension_elliptic_curves = TlsExtensionEllipticCurves.parse_exact_size(extension_elliptic_curves_bytes)
        self.assertEqual(
            list(extension_elliptic_curves.elliptic_curves),
            [
                TlsNamedCurve.X25519,
                TlsNamedCurve.SECP256R1,
                TlsNamedCurve.SECP384R1,
                TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A),
            ]
        )
        self.assertEqual(extension_elliptic_curves.compose(), extension_elliptic_curves_bytes)


class TestExtensionSupportedVersions(unittest.TestCase):
    def test_parse(self):
        extension_supported_versions_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x2b'),
            ('extension_length', b'\x00\x09'),
            ('supported_version_list_length', b'\x08'),
            ('supported_version_list', b'\x03\x02\x03\x03\x7f\x18\x0a\x0a'),
        ])
        extension_supported_versions_bytes = b''.join(extension_supported_versions_dict.values())
        extension_supported_versions = TlsExtensionSupportedVersionsClient.parse_exact_size(
            extension_supported_versions_bytes
        )
        self.assertEqual(
            list(extension_supported_versions.supported_versions),
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                TlsProtocolVersionDraft(24),
                TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A),
            ]
        )
        self.assertEqual(extension_supported_versions.compose(), extension_supported_versions_bytes)

        extension_supported_versions_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x2b'),
            ('extension_length', b'\x00\x02'),
            ('selected_version', b'\x03\x03'),
        ])
        extension_supported_versions_bytes = b''.join(extension_supported_versions_dict.values())
        extension_supported_versions = TlsExtensionSupportedVersionsServer.parse_exact_size(
            extension_supported_versions_bytes
        )
        self.assertEqual(
            extension_supported_versions.selected_version,
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(extension_supported_versions.compose(), extension_supported_versions_bytes)


class TestExtensionTokenBinding(unittest.TestCase):
    def test_parse(self):
        extension_token_binding_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x18'),
            ('extension_length', b'\x00\x06'),
            ('protocol_version', b'\x01\x02'),
            ('supported_version_list', b'\x03\x02\x01\x00'),
        ])
        extension_token_binding_bytes = b''.join(extension_token_binding_dict.values())
        extension_token_binding = TlsExtensionTokenBinding.parse_exact_size(
            extension_token_binding_bytes
        )
        self.assertEqual(
            list(extension_token_binding.parameters),
            [
                TlsTokenBindingParamater.ECDSAP256,
                TlsTokenBindingParamater.RSA2048_PSS,
                TlsTokenBindingParamater.RSA2048_PKCS1_5,
            ]
        )
        self.assertEqual(
            extension_token_binding.protocol_version,
            TlsTokenBindingProtocolVersion(1, 2),
        )
        self.assertEqual(extension_token_binding.compose(), extension_token_binding_bytes)


class TestExtensionSignatureAlgorithms(unittest.TestCase):
    def test_parse(self):
        extension_signature_algorithms_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0d'),
            ('extension_length', b'\x00\x0c'),
            ('signature_algorithm_list_length', b'\x00\x0a'),
            ('signature_algorithm_list', b'\x01\x00\x02\x01\x03\x02\x04\x03\x0a\x0a'),
        ])
        extension_signature_algorithms_bytes = b''.join(extension_signature_algorithms_dict.values())
        extension_signature_algorithms = TlsExtensionSignatureAlgorithms.parse_exact_size(
            extension_signature_algorithms_bytes
        )
        self.assertEqual(extension_signature_algorithms.extension_type, TlsExtensionType.SIGNATURE_ALGORITHMS)
        self.assertEqual(
            list(extension_signature_algorithms.hash_and_signature_algorithms),
            [
                TlsSignatureAndHashAlgorithm.ANONYMOUS_MD5,
                TlsSignatureAndHashAlgorithm.RSA_SHA1,
                TlsSignatureAndHashAlgorithm.DSA_SHA224,
                TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
                TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A),
            ]
        )
        self.assertEqual(extension_signature_algorithms.compose(), extension_signature_algorithms_bytes)


class TestExtensionSignatureAlgorithmsCert(unittest.TestCase):
    def test_parse(self):
        extension_signature_algorithms_cert_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x32'),
            ('extension_length', b'\x00\x0a'),
            ('signature_algorithm_list_length', b'\x00\x08'),
            ('signature_algorithm_list', b'\x01\x00\x02\x01\x03\x02\x04\x03'),
        ])
        extension_signature_algorithms_cert_bytes = b''.join(extension_signature_algorithms_cert_dict.values())
        extension_signature_algorithms_cert = TlsExtensionSignatureAlgorithmsCert.parse_exact_size(
            extension_signature_algorithms_cert_bytes
        )
        self.assertEqual(extension_signature_algorithms_cert.extension_type, TlsExtensionType.SIGNATURE_ALGORITHMS_CERT)
        self.assertEqual(
            list(extension_signature_algorithms_cert.hash_and_signature_algorithms),
            [
                TlsSignatureAndHashAlgorithm.ANONYMOUS_MD5,
                TlsSignatureAndHashAlgorithm.RSA_SHA1,
                TlsSignatureAndHashAlgorithm.DSA_SHA224,
                TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            ]
        )
        self.assertEqual(extension_signature_algorithms_cert.compose(), extension_signature_algorithms_cert_bytes)


class TestExtensionSignedCertificateTimestamp(unittest.TestCase):
    def test_parse_minimal(self):
        extension_signed_certificate_timestamp_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x12'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_signed_certificate_timestamp_bytes = b''.join(extension_signed_certificate_timestamp_dict.values())
        extension_signed_certificate_timestamp = TlsExtensionSignedCertificateTimestamp.parse_exact_size(
            extension_signed_certificate_timestamp_bytes
        )
        self.assertEqual(
            extension_signed_certificate_timestamp.extension_type, TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
        )
        self.assertEqual(extension_signed_certificate_timestamp.scts, None)
        self.assertEqual(extension_signed_certificate_timestamp.compose(), extension_signed_certificate_timestamp_bytes)

    def test_parse_full(self):
        extension_signed_certificate_timestamp_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x12'),
            ('extension_length', b'\x00\x0e'),
            ('signed_certificate_timestamp_list', b'\x00\x0c\x00\x04\x00\x01\x02\x03\x00\x04\x04\x05\x06\x07'),
        ])
        extension_signed_certificate_timestamp_bytes = b''.join(extension_signed_certificate_timestamp_dict.values())
        extension_signed_certificate_timestamp = TlsExtensionSignedCertificateTimestamp.parse_exact_size(
            extension_signed_certificate_timestamp_bytes
        )
        self.assertEqual(
            extension_signed_certificate_timestamp.extension_type, TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
        )
        self.assertEqual(
            list(extension_signed_certificate_timestamp.scts),
            [SerializedSCT(b'\x00\x01\x02\x03'), SerializedSCT(b'\x04\x05\x06\x07')]
        )
        self.assertEqual(extension_signed_certificate_timestamp.compose(), extension_signed_certificate_timestamp_bytes)


class TestExtensionKeyShareClient(unittest.TestCase):
    def test_parse(self):
        extension_key_share_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x33'),
            ('extension_length', b'\x00\x2a'),
            ('key_share_length', b'\x00\x28'),
            ('group_grease', b'\x0a\x0a'),
            ('key_exchange_length_grease', b'\x00\x00'),
            ('group', b'\x00\x1d'),
            ('key_exchange_length', b'\x00\x20'),
            ('key_exchange',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'')
        ])
        extension_key_share_bytes = b''.join(extension_key_share_dict.values())
        extension_key_share = TlsExtensionKeyShareClient.parse_exact_size(
            extension_key_share_bytes
        )
        key_share_entries = extension_key_share.key_share_entries
        self.assertEqual(len(key_share_entries), 2)
        self.assertEqual(key_share_entries[0].group, TlsInvalidTypeTwoByte(TlsGreaseTwoByte.GREASE_0A0A))
        self.assertEqual(key_share_entries[1].group, TlsNamedCurve.X25519)
        self.assertEqual(
            bytearray(key_share_entries[1].key_exchange),
            extension_key_share_dict['key_exchange']
        )
        self.assertEqual(extension_key_share.compose(), extension_key_share_bytes)


class TestExtensionKeyShareReservedClient(unittest.TestCase):
    def test_parse(self):
        extension_key_share_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x28'),
            ('extension_length', b'\x00\x26'),
            ('key_share_length', b'\x00\x24'),
            ('group', b'\x00\x1d'),
            ('key_exchange_length', b'\x00\x20'),
            ('key_exchange',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'')
        ])
        extension_key_share_bytes = b''.join(extension_key_share_dict.values())
        extension_key_share = TlsExtensionKeyShareReservedClient.parse_exact_size(
            extension_key_share_bytes
        )
        key_share_entries = extension_key_share.key_share_entries  # pylint: disable=no-member
        self.assertEqual(len(key_share_entries), 1)
        self.assertEqual(key_share_entries[0].group, TlsNamedCurve.X25519)
        self.assertEqual(
            bytearray(key_share_entries[0].key_exchange),
            extension_key_share_dict['key_exchange']
        )
        self.assertEqual(extension_key_share.compose(), extension_key_share_bytes)


class TestExtensionKeyShareClientHelloRetry(unittest.TestCase):
    def test_error(self):
        extension_key_share_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x33'),
            ('extension_length', b'\x00\x04'),
            ('data', b'\x00\x00\x00\x00'),
        ])
        extension_key_share_bytes = b''.join(extension_key_share_dict.values())

        with self.assertRaises(InvalidType):
            # pylint: disable=expression-not-assigned
            TlsExtensionKeyShareClientHelloRetry.parse_exact_size(
                extension_key_share_bytes
            )

    def test_parse(self):
        extension_key_share_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x33'),
            ('extension_length', b'\x00\x02'),
            ('group', b'\x00\x1d'),
        ])
        extension_key_share_bytes = b''.join(extension_key_share_dict.values())
        extension_key_share = TlsExtensionKeyShareClientHelloRetry.parse_exact_size(
            extension_key_share_bytes
        )
        self.assertEqual(extension_key_share.selected_group, TlsNamedCurve.X25519)
        self.assertEqual(extension_key_share.compose(), extension_key_share_bytes)


class TestExtensionKeyShareServer(unittest.TestCase):
    def test_parse(self):
        extension_key_share_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x33'),
            ('extension_length', b'\x00\x24'),
            ('group', b'\x00\x1d'),
            ('key_exchange_length', b'\x00\x20'),
            ('key_exchange',
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'\x00\x01\x02\x03\x04\x05\x06\x07' +
             b'')
        ])
        extension_key_share_bytes = b''.join(extension_key_share_dict.values())
        extension_key_share = TlsExtensionKeyShareServer.parse_exact_size(
            extension_key_share_bytes
        )
        self.assertEqual(extension_key_share.key_share_entry.group, TlsNamedCurve.X25519)
        self.assertEqual(
            bytearray(extension_key_share.key_share_entry.key_exchange),
            extension_key_share_dict['key_exchange']
        )
        self.assertEqual(extension_key_share.compose(), extension_key_share_bytes)


class TestExtensionCertificateStatusRequest(unittest.TestCase):
    def setUp(self):
        self.status_request_empty_bytes = bytes(
            b'\x00\x05' +                          # handshake_type = STATUS_REQUEST
            b'\x00\x00' +                          # length = 0x05
            b''
        )
        self.status_request_empty = TlsExtensionCertificateStatusRequest()

        self.status_request_minimal_bytes = bytes(
            b'\x00\x05' +                          # handshake_type = STATUS_REQUEST
            b'\x00\x05' +                          # length = 0x05
            b'\x01' +                              # status_type = OCSP
            b'\x00\x00' +                          # responder_id_list_length = 0x00
            b'\x00\x00' +                          # request_extensions_length = 0x00
            b''
        )
        self.status_request_minimal = TlsExtensionCertificateStatusRequest()

        self.request_extensions = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        self.status_request_bytes = bytes(
            b'\x00\x05' +                          # handshake_type = STATUS_REQUEST
            b'\x00\x15' +                          # length = 0x05
            b'\x01' +                              # status_type = OCSP
            b'\x00\x08' +                          # responder_id_list_length = 0x08
            b'\x00\x01\x00\x00\x03\x01\x02\x03' +  # responder_id_list
            b'\x00\x08' +                          # request_extensions_length = 0x08
            self.request_extensions +              # request_extensions
            b''
        )
        self.status_request = TlsExtensionCertificateStatusRequest(
            responder_id_list=TlsCertificateStatusRequestResponderIdList([
                TlsCertificateStatusRequestResponderId(b'\x00'),
                TlsCertificateStatusRequestResponderId(b'\x01\x02\x03')
            ]),
            extensions=TlsCertificateStatusRequestExtensions(self.request_extensions)
        )

    def test_parse(self):
        status_request_empty = TlsExtensionCertificateStatusRequest.parse_exact_size(
            self.status_request_empty_bytes
        )
        self.assertEqual(status_request_empty.responder_id_list, TlsCertificateStatusRequestResponderIdList([]))
        self.assertEqual(status_request_empty.request_extensions, TlsCertificateStatusRequestExtensions([]))

        status_request_minimal = TlsExtensionCertificateStatusRequest.parse_exact_size(
            self.status_request_minimal_bytes
        )
        self.assertEqual(status_request_minimal.responder_id_list, TlsCertificateStatusRequestResponderIdList([]))
        self.assertEqual(status_request_minimal.request_extensions, TlsCertificateStatusRequestExtensions([]))

        status_request = TlsExtensionCertificateStatusRequest.parse_exact_size(self.status_request_bytes)
        self.assertEqual(
            status_request.responder_id_list,
            TlsCertificateStatusRequestResponderIdList([
                TlsCertificateStatusRequestResponderId(b'\x00'),
                TlsCertificateStatusRequestResponderId(b'\x01\x02\x03')
            ])
        )
        self.assertEqual(
            status_request.request_extensions,
            TlsCertificateStatusRequestExtensions(self.request_extensions)
        )

    def test_compose(self):
        self.assertEqual(self.status_request_minimal.compose(), self.status_request_minimal_bytes)
        self.assertEqual(self.status_request.compose(), self.status_request_bytes)


class TestTlsExtensionPskKeyExchangeModes(unittest.TestCase):
    def test_parse(self):
        extension_pks_key_exchange_modes_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x2d'),
            ('extension_length', b'\x00\x03'),
            ('supported_version_list', b'\x02\x01\x00'),
        ])
        extension_pks_key_exchange_modes_bytes = b''.join(extension_pks_key_exchange_modes_dict.values())
        extension_pks_key_exchange_modes = TlsExtensionPskKeyExchangeModes.parse_exact_size(
            extension_pks_key_exchange_modes_bytes
        )
        self.assertEqual(
            list(extension_pks_key_exchange_modes.key_exchange_modes),
            [
                TlsPskKeyExchangeMode.PSK_DH_KE,
                TlsPskKeyExchangeMode.PSK_KE,
            ]
        )
        self.assertEqual(extension_pks_key_exchange_modes.compose(), extension_pks_key_exchange_modes_bytes)


class TestExtensionRenegotiationInfo(unittest.TestCase):
    def test_parse(self):
        extension_renegotiation_info_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x09'),
            ('renegotiated_connection_length', b'\x08'),
            ('renegotiated_connection', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
        ])
        extension_renegotiation_info_bytes = b''.join(extension_renegotiation_info_dict.values())
        extension_renegotiation_info = TlsExtensionRenegotiationInfo.parse_exact_size(
            extension_renegotiation_info_bytes
        )
        self.assertEqual(
            extension_renegotiation_info.renegotiated_connection,
            TlsRenegotiatedConnection(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        )
        self.assertEqual(extension_renegotiation_info.compose(), extension_renegotiation_info_bytes)


class TestExtensionSessionTicket(unittest.TestCase):
    def test_parse(self):
        extension_session_ticket_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x23'),
            ('extension_length', b'\x00\x08'),
            ('session_ticket', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
        ])
        extension_session_ticket_bytes = b''.join(extension_session_ticket_dict.values())
        extension_session_ticket = TlsExtensionSessionTicket.parse_exact_size(
            extension_session_ticket_bytes
        )
        self.assertEqual(extension_session_ticket.session_ticket, b'\x00\x01\x02\x03\x04\x05\x06\x07')
        self.assertEqual(extension_session_ticket.compose(), extension_session_ticket_bytes)


class TestExtensionNextProtocolNegotiationClient(unittest.TestCase):
    def test_parse(self):
        extension_next_protocol_names_dict = collections.OrderedDict([
            ('extension_type', b'\x33\x74'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_next_protocol_names_bytes = b''.join(extension_next_protocol_names_dict.values())
        extension_next_protocol_names_mac = TlsExtensionNextProtocolNegotiationClient.parse_exact_size(
            extension_next_protocol_names_bytes
        )
        self.assertEqual(extension_next_protocol_names_mac.compose(), extension_next_protocol_names_bytes)


class TestExtensionNextProtocolNegotiationServer(unittest.TestCase):
    def test_parse(self):
        extension_next_protocol_names_dict = collections.OrderedDict([
            ('extension_type', b'\x33\x74'),
            ('extension_length', b'\x00\x10'),
            ('protocol_name_h2_length', b'\x08'),
            ('protocol_name_h2', b'http/1.1'),
            ('protocol_name_h2c_length', b'\x06'),
            ('protocol_name_h2c', b'spdy/1'),
        ])
        extension_next_protocol_names_bytes = b''.join(extension_next_protocol_names_dict.values())
        extension_next_protocol_names = TlsExtensionNextProtocolNegotiationServer.parse_exact_size(
            extension_next_protocol_names_bytes
        )
        self.assertEqual(
            extension_next_protocol_names.protocol_names,
            TlsNextProtocolNameList([TlsNextProtocolName.HTTP_1_1, TlsNextProtocolName.SPDY_1])
        )
        self.assertEqual(extension_next_protocol_names.compose(), extension_next_protocol_names_bytes)


class TestExtensionApplicationLayerProtocolNegotiation(unittest.TestCase):
    def test_parse(self):
        extension_alpn_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x10'),
            ('extension_length', b'\x00\x09'),
            ('protocol_name_list_length', b'\x00\x07'),
            ('protocol_name_h2_length', b'\x02'),
            ('protocol_name_h2', b'h2'),
            ('protocol_name_h2c_length', b'\x03'),
            ('protocol_name_h2c', b'h2c'),
        ])
        extension_alpn_bytes = b''.join(extension_alpn_dict.values())
        extension_alpn = TlsExtensionApplicationLayerProtocolNegotiation.parse_exact_size(
            extension_alpn_bytes
        )
        self.assertEqual(extension_alpn.protocol_names, TlsProtocolNameList([TlsProtocolName.H2, TlsProtocolName.H2C]))
        self.assertEqual(extension_alpn.compose(), extension_alpn_bytes)


class TestExtensionApplicationLayerProtocolSettings(unittest.TestCase):
    def test_parse(self):
        extension_alpn_dict = collections.OrderedDict([
            ('extension_type', b'\x44\x69'),
            ('extension_length', b'\x00\x09'),
            ('protocol_name_list_length', b'\x00\x07'),
            ('protocol_name_h2_length', b'\x02'),
            ('protocol_name_h2', b'h2'),
            ('protocol_name_h2c_length', b'\x03'),
            ('protocol_name_h2c', b'h2c'),
        ])
        extension_alpn_bytes = b''.join(extension_alpn_dict.values())
        extension_alpn = TlsExtensionApplicationLayerProtocolSettings.parse_exact_size(
            extension_alpn_bytes
        )
        self.assertEqual(extension_alpn.protocol_names, TlsProtocolNameList([TlsProtocolName.H2, TlsProtocolName.H2C]))
        self.assertEqual(extension_alpn.compose(), extension_alpn_bytes)


class TestExtensionUnusedData(unittest.TestCase):
    def test_error(self):
        extension_unused_data_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x01'),
            ('extension_data', b'\xff'),
        ])
        extension_unused_data_bytes = b''.join(extension_unused_data_dict.values())
        with self.assertRaises(InvalidValue) as context_manager:
            # pylint: disable=expression-not-assigned
            TestUnusedDataExtension.parse_exact_size(extension_unused_data_bytes)
        self.assertEqual(context_manager.exception.value, b'\xff')


class TestExtensionEncryptThenMAC(unittest.TestCase):
    def test_parse(self):
        extension_encrypt_then_mac_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x16'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_encrypt_then_mac_bytes = b''.join(extension_encrypt_then_mac_dict.values())
        extension_encrypt_then_mac = TlsExtensionEncryptThenMAC.parse_exact_size(extension_encrypt_then_mac_bytes)
        self.assertEqual(extension_encrypt_then_mac.compose(), extension_encrypt_then_mac_bytes)


class TestExtensionExtendedMasterSecret(unittest.TestCase):
    def test_parse(self):
        extension_extended_master_secret_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x17'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_extended_master_secret_bytes = b''.join(extension_extended_master_secret_dict.values())
        extended_master_secret = TlsExtensionExtendedMasterSecret.parse_exact_size(
            extension_extended_master_secret_bytes
        )
        self.assertEqual(extended_master_secret.compose(), extension_extended_master_secret_bytes)


class TestExtensionRecordSizeLimit(unittest.TestCase):
    def test_parse(self):
        extension_record_size_limit_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x1c'),
            ('extension_length', b'\x00\x02'),
            ('record_size_limit', b'\x00\xff'),
        ])
        extension_record_size_limit_bytes = b''.join(extension_record_size_limit_dict.values())
        extension_record_size_limit = TlsExtensionRecordSizeLimit.parse_exact_size(extension_record_size_limit_bytes)
        self.assertEqual(extension_record_size_limit.record_size_limit, 0xff)
        self.assertEqual(extension_record_size_limit.compose(), extension_record_size_limit_bytes)
