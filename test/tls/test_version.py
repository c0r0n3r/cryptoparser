# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import Grade

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion


class TestTlsProtocolVersion(unittest.TestCase):
    def test_parse(self):
        parsable = b'\x03\xff'
        expected_error_message = ' is not a valid TlsVersionFactory'
        with self.assertRaisesRegex(InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            TlsProtocolVersion.parse_exact_size(parsable)

        expected_error_message = ' is not a valid TlsVersionFactory'
        with self.assertRaisesRegex(InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            TlsProtocolVersion.parse_exact_size(b'\x8f\x00')

        with self.assertRaises(NotEnoughData) as context_manager:
            TlsProtocolVersion.parse_exact_size(b'\xff')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_compose(self):
        self.assertEqual(
            b'\x03\x03',
            TlsProtocolVersion(TlsVersion.TLS1_2).compose()
        )

        self.assertEqual(
            b'\x7f\x12',
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_18).compose()
        )

    def test_lt(self):
        self.assertLess(
            TlsProtocolVersion(TlsVersion.SSL2),
            TlsProtocolVersion(TlsVersion.SSL3)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.SSL3),
            TlsProtocolVersion(TlsVersion.SSL2)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.SSL3),
            TlsProtocolVersion(TlsVersion.TLS1)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1),
            TlsProtocolVersion(TlsVersion.SSL3)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_1),
            TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsProtocolVersion(TlsVersion.TLS1_1)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_1),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_2)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_2),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_1)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_0)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_0),
            TlsProtocolVersion(TlsVersion.TLS1_2)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            TlsProtocolVersion(TlsVersion.TLS1_3)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_3),
            TlsProtocolVersion(TlsVersion.TLS1_2)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28),
            TlsProtocolVersion(TlsVersion.TLS1_3)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_3),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28)
        )

        self.assertLess(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_0),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28)
        )
        self.assertGreater(
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_0)
        )

    def test_set(self):
        self.assertEqual(
            2,
            len(set([
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2)
            ]))
        )
        self.assertEqual(
            1,
            len(set([
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_1)
            ]))
        )

        self.assertEqual(
            2,
            len(set([
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_1),
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_2)
            ]))
        )
        self.assertEqual(
            1,
            len(set([
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_1),
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_1)
            ]))
        )

    def test_as_json(self):
        self.assertEqual(TlsProtocolVersion(TlsVersion.SSL3).as_json(), '\"ssl3\"')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1).as_json(), '\"tls1\"')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_2).as_json(), '\"tls1_2\"')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_24).as_json(), '\"tls1_3_draft_24\"')
        self.assertEqual(
            TlsProtocolVersion(TlsVersion.TLS1_3_GOOGLE_EXPERIMENT_2).as_json(),
            '\"tls1_3_google_experiment_2\"'
        )

    def test_as_markdown(self):
        self.assertEqual(TlsProtocolVersion(TlsVersion.SSL3).as_markdown(), 'SSL 3.0')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1).as_markdown(), 'TLS 1.0')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_2).as_markdown(), 'TLS 1.2')
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_24).as_markdown(), 'TLS 1.3 Draft 24')
        self.assertEqual(
            TlsProtocolVersion(TlsVersion.TLS1_3_GOOGLE_EXPERIMENT_2).as_markdown(),
            'TLS 1.3 Google Experiment 2'
        )

    def test_str(self):
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.SSL2)), 'SSL 2.0')
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.SSL3)), 'SSL 3.0')
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.TLS1)), 'TLS 1.0')
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.TLS1_2)), 'TLS 1.2')
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_24)), 'TLS 1.3 Draft 24')
        self.assertEqual(str(TlsProtocolVersion(TlsVersion.TLS1_3_GOOGLE_EXPERIMENT_2)), 'TLS 1.3 Google Experiment 2')

    def test_grade(self):
        self.assertEqual(TlsProtocolVersion(TlsVersion.SSL2).grade, Grade.INSECURE)
        self.assertEqual(TlsProtocolVersion(TlsVersion.SSL3).grade, Grade.INSECURE)
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1).grade, Grade.DEPRECATED)
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_1).grade, Grade.DEPRECATED)
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28).grade, Grade.DEPRECATED)
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_2).grade, Grade.SECURE)
        self.assertEqual(TlsProtocolVersion(TlsVersion.TLS1_3).grade, Grade.SECURE)
