# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.grade import Grade

from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.ike.version import IsakmpProtocolVersion, IsakmpVersion, IsakmpVersionFactory


class TestIsakmpProtocolVersion(unittest.TestCase):
    def setUp(self):
        self.version_bytes = b'\x11'
        self.version = IsakmpProtocolVersion(IsakmpVersion.V1, 1)

    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            IsakmpProtocolVersion.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        with self.assertRaises(InvalidType):
            IsakmpProtocolVersion.parse_exact_size(b'\x00')

    def test_parse(self):
        version = IsakmpProtocolVersion.parse_exact_size(self.version_bytes)
        self.assertEqual(version.major, IsakmpVersion.V1)
        self.assertEqual(version.minor, 1)

    def test_compose(self):
        self.assertEqual(self.version.compose(), self.version_bytes)

    def test_versions(self):
        version_1_0 = IsakmpProtocolVersion(IsakmpVersion.V1, 0)
        self.assertEqual(version_1_0.compose(), b'\x10')
        self.assertEqual(IsakmpProtocolVersion.parse_exact_size(b'\x10'), version_1_0)

        version_1_1 = IsakmpProtocolVersion(IsakmpVersion.V1, 1)
        self.assertEqual(version_1_1.compose(), b'\x11')
        self.assertEqual(IsakmpProtocolVersion.parse_exact_size(b'\x11'), version_1_1)

        version_2_0 = IsakmpProtocolVersion(IsakmpVersion.V2, 0)
        self.assertEqual(version_2_0.compose(), b'\x20')
        self.assertEqual(IsakmpProtocolVersion.parse_exact_size(b'\x20'), version_2_0)

    def test_identifier(self):
        self.assertEqual(IsakmpVersion.V1.identifier, "ikev1")
        self.assertEqual(IsakmpVersion.V2.identifier, "ikev2")

    def test_grade(self):
        version_v1 = IsakmpProtocolVersion(IsakmpVersion.V1, 0)
        self.assertEqual(version_v1.grade, Grade.DEPRECATED)

        version_v2 = IsakmpProtocolVersion(IsakmpVersion.V2, 0)
        self.assertEqual(version_v2.grade, Grade.SECURE)

    def test_str(self):
        version_1_1 = IsakmpProtocolVersion(IsakmpVersion.V1, 1)
        self.assertEqual(str(version_1_1), "IKEv1 (1)")

        version_2_0 = IsakmpProtocolVersion(IsakmpVersion.V2, 0)
        self.assertEqual(str(version_2_0), "IKEv2 (0)")

    def test_version(self):
        version_1_1 = IsakmpProtocolVersion(IsakmpVersion.V1, 1)
        self.assertEqual(version_1_1.version, "1.1")

        version_2_0 = IsakmpProtocolVersion(IsakmpVersion.V2, 0)
        self.assertEqual(version_2_0.version, "2.0")


class TestIsakmpVersionFactory(unittest.TestCase):
    def test_get_enum_class(self):
        self.assertEqual(IsakmpVersionFactory.get_enum_class(), IsakmpVersion)
