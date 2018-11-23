#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import unittest

from cryptoparser.common.exception import NotEnoughData, InvalidValue, InvalidType
from cryptoparser.tls.extension import TlsExtensionUnparsed, TlsExtensionParsed
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, TlsProtocolVersionDraft

from cryptoparser.tls.extension import TlsExtensionServerName
from cryptoparser.tls.extension import TlsExtensionECPointFormats, TlsECPointFormat
from cryptoparser.tls.extension import TlsExtensionEllipticCurves, TlsNamedCurve
from cryptoparser.tls.extension import TlsExtensionSupportedVersions
from cryptoparser.tls.extension import TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm
from cryptoparser.tls.extension import TlsExtensionCertificateStatusRequest
from cryptoparser.tls.extension import TlsCertificateStatusRequestResponderId
from cryptoparser.tls.extension import TlsCertificateStatusRequestResponderIdList
from cryptoparser.tls.extension import TlsCertificateStatusRequestExtensions
from cryptoparser.tls.extension import TlsExtensionRenegotiationInfo, TlsRenegotiatedConnection
from cryptoparser.tls.extension import TlsExtensionSessionTicket
from cryptoparser.tls.extension import TlsExtensionApplicationLayerProtocolNegotiation
from cryptoparser.tls.extension import TlsProtocolNameList, TlsProtocolName
from cryptoparser.tls.extension import TlsExtensionGrease, TLS_EXTENSION_TYPES_GREASE


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
        self.assertEqual(extension_hostname_internationalized.host_name, u'ísland.icom.museum')
        self.assertEqual(extension_hostname_internationalized.compose(), extension_hostname_internationalized_bytes)


class TestExtensionECPointFormat(unittest.TestCase):
    def test_parse(self):
        extension_ec_point_formats_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0b'),
            ('extension_length', b'\x00\x02'),
            ('ec_point_format_list_length', b'\x01'),
            ('ec_point_format_list', b'\x00'),
        ])
        extension_ec_point_formats_bytes = b''.join(extension_ec_point_formats_dict.values())

        extension_point_formats = TlsExtensionECPointFormats.parse_exact_size(extension_ec_point_formats_bytes)
        self.assertEqual(list(extension_point_formats.point_formats), [TlsECPointFormat.UNCOMPRESSED, ])
        self.assertEqual(extension_point_formats.compose(), extension_ec_point_formats_bytes)


class TestExtensionEllipticCurves(unittest.TestCase):
    def test_parse(self):
        extension_elliptic_curves_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0a'),
            ('extension_length', b'\x00\x08'),
            ('elliptic_curve_list_length', b'\x00\x06'),
            ('elliptic_curve_list', b'\x00\x1d\x00\x17\x00\x18'),
        ])
        extension_elliptic_curves_bytes = b''.join(extension_elliptic_curves_dict.values())

        extension_elliptic_curves = TlsExtensionEllipticCurves.parse_exact_size(extension_elliptic_curves_bytes)
        self.assertEqual(
            list(extension_elliptic_curves.elliptic_curves),
            [
                TlsNamedCurve.X25519,
                TlsNamedCurve.SECP256R1,
                TlsNamedCurve.SECP384R1,
            ]
        )
        self.assertEqual(extension_elliptic_curves.compose(), extension_elliptic_curves_bytes)


class TestExtensionSupportedVersions(unittest.TestCase):
    def test_parse(self):
        extension_supported_versions_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x2b'),
            ('extension_length', b'\x00\x07'),
            ('supported_version_list_length', b'\x06'),
            ('supported_version_list', b'\x03\x02\x03\x03\x7f\x18'),
        ])
        extension_supported_versions_bytes = b''.join(extension_supported_versions_dict.values())
        extension_supported_versions = TlsExtensionSupportedVersions.parse_exact_size(
            extension_supported_versions_bytes
        )
        self.assertEqual(
            list(extension_supported_versions.supported_versions),
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                TlsProtocolVersionDraft(24),
            ]
        )
        self.assertEqual(extension_supported_versions.compose(), extension_supported_versions_bytes)


class TestExtensionSignatureAlgorithms(unittest.TestCase):
    def test_parse(self):
        extension_signature_algorithms_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0d'),
            ('extension_length', b'\x00\x0a'),
            ('signature_algorithm_list_length', b'\x00\x08'),
            ('signature_algorithm_list', b'\x01\x00\x02\x01\x03\x02\x04\x03'),
        ])
        extension_signature_algorithms_bytes = b''.join(extension_signature_algorithms_dict.values())
        extension_signature_algorithms = TlsExtensionSignatureAlgorithms.parse_exact_size(
            extension_signature_algorithms_bytes
        )
        self.assertEqual(
            list(extension_signature_algorithms.hash_and_signature_algorithms),
            [
                TlsSignatureAndHashAlgorithm.ANONYMOUS_MD5,
                TlsSignatureAndHashAlgorithm.RSA_SHA1,
                TlsSignatureAndHashAlgorithm.DSA_SHA224,
                TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            ]
        )
        self.assertEqual(extension_signature_algorithms.compose(), extension_signature_algorithms_bytes)


class TestExtensionCertificateStatusRequest(unittest.TestCase):
    def setUp(self):
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
        self.assertEqual(extension_renegotiation_info.renegotiated_connection, TlsRenegotiatedConnection(b'\x00\x01\x02\x03\x04\x05\x06\x07'))
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


class TestExtensionGrease(unittest.TestCase):
    def test_parse(self):
        for extension_type in TLS_EXTENSION_TYPES_GREASE:
            extension_grease_dict = collections.OrderedDict([
                ('extension_type', bytearray.fromhex('{:04x}'.format(extension_type))),
                ('extension_length', b'\x00\x00'),
            ])
            extension_grease_bytes = b''.join(extension_grease_dict.values())
            extension_grease = TlsExtensionGrease.parse_exact_size(
                extension_grease_bytes
            )
            self.assertEqual(extension_grease.get_extension_type(), extension_type)
            self.assertEqual(extension_grease.compose(), extension_grease_bytes)
