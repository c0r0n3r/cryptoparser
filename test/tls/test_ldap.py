# -*- coding: utf-8 -*-

import copy

import unittest
import collections

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.ldap import (
    LDAPExtendedRequestStartTLS,
    LDAPExtendedResponseStartTLS,
    LDAPResultCode,
)


class TestLDAPExtendedRequest(unittest.TestCase):
    def setUp(self):
        self.ldap_extended_request_dict = collections.OrderedDict([
            ('message_sequence', b'\x30\x1d'),
            ('message_id', b'\x02\x01\x01'),
            ('protocol_op', b'\x77\x18'),
            ('extended_request', b'\x80'),
            ('request_name', (
                b'\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36' +
                b'\x36\x2e\x32\x30\x30\x33\x37'
            )),
        ])
        self.ldap_extended_request_bytes = b''.join(self.ldap_extended_request_dict.values())

        self.ldap_extended_request = LDAPExtendedRequestStartTLS()

    def test_parse(self):
        LDAPExtendedRequestStartTLS.parse_exact_size(self.ldap_extended_request_bytes)

    def test_compose(self):
        self.assertEqual(self.ldap_extended_request.compose(), self.ldap_extended_request_bytes)


class TestLDAPExtendedResponseMinimal(unittest.TestCase):
    def setUp(self):
        self.ldap_extended_response_dict = collections.OrderedDict([
            ('message_sequence', b'\x30\x0c'),
            ('message_id', b'\x02\x01\x01'),
            ('protocol_op', b'\x78\x07'),
            ('extended_response', b''),
            ('result_code', b'\x0a\x01\x07'),
            ('matched_dn', b'\x04\x00'),
            ('diagnostic_message', b'\x04\x00'),
            ('referral', b''),
        ])
        self.ldap_extended_response_bytes = b''.join(self.ldap_extended_response_dict.values())

        self.ldap_extended_response = LDAPExtendedResponseStartTLS(LDAPResultCode.AUTH_METHOD_NOT_SUPPORTED)

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            LDAPExtendedResponseStartTLS.parse_exact_size(
                    self.ldap_extended_response_bytes[:LDAPExtendedResponseStartTLS.HEADER_SIZE]
            )
        self.assertEqual(
            context_manager.exception.bytes_needed,
            len(self.ldap_extended_response_bytes) - LDAPExtendedResponseStartTLS.HEADER_SIZE
        )

        ldap_extended_response_dict = copy.copy(self.ldap_extended_response_dict)
        ldap_extended_response_dict['protocol_op'] = b'\xff\xff'
        ldap_extended_response_bytes = b''.join(ldap_extended_response_dict.values())

        with self.assertRaises(InvalidValue) as context_manager:
            # pylint: disable=expression-not-assigned
            LDAPExtendedResponseStartTLS.parse_exact_size(ldap_extended_response_bytes)

    def test_parse(self):
        ldap_extended_response = LDAPExtendedResponseStartTLS.parse_exact_size(self.ldap_extended_response_bytes)
        self.assertEqual(ldap_extended_response.result_code, self.ldap_extended_response.result_code)

    def test_compose(self):
        self.assertEqual(self.ldap_extended_response.compose(), self.ldap_extended_response_bytes)


class TestLDAPExtendedResponseFull(unittest.TestCase):
    def setUp(self):
        self.ldap_extended_response_dict = collections.OrderedDict([
            ('message_sequence', b'\x30\x34'),
            ('message_id', b'\x02\x01\x01'),
            ('protocol_op', b'\x78\x2f'),
            ('extended_response', b''),
            ('result_code', b'\x0a\x01\x07'),
            ('matched_dn', b'\x04\x08\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('diagnostic_message', b'\x04\x08\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('referral', b''),
            ('response_name', (
                b'\x8a\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34' +
                b'\x36\x36\x2e\x32\x30\x30\x33\x37'
            )),
        ])
        self.ldap_extended_response_bytes = b''.join(self.ldap_extended_response_dict.values())

        self.ldap_extended_response = LDAPExtendedResponseStartTLS(LDAPResultCode.AUTH_METHOD_NOT_SUPPORTED)

    def test_parse(self):
        ldap_extended_response = LDAPExtendedResponseStartTLS.parse_exact_size(self.ldap_extended_response_bytes)
        self.assertEqual(ldap_extended_response.result_code, self.ldap_extended_response.result_code)
