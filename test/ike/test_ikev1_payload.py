# -*- coding: utf-8 -*-

import collections
import unittest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev1PayloadType, Ikev1AttributeType, Ikev1AuthenticationMethod, Ikev1DiffieHellmanGroup,
    Ikev1HashAlgorithm, Ikev1LifeType, Ikev1TransformId, Ikev1EncryptionAlgorithm,
    Ikev1Doi, Ikev1ProtocolId, Ikev1NotifyType
)

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod, Ikev1AttributeDiffieHellmanGroup, Ikev1AttributeHashAlgorithm,
    Ikev1AttributeLifeType, Ikev1AttributeLifeDuration, Ikev1AttributeKeyLength, Ikev1AttributeEncryptionAlgorithm,
    Ikev1PayloadTransform, Ikev1PayloadKeyExchange, Ikev1PayloadNonce, Ikev1PayloadNotification, Ikev1PayloadVendorId
)

from .classes import Ikev1PayloadBaseTest


class TestIkev1PayloadBaseTest(unittest.TestCase):
    """Test the Ikev1PayloadBaseTest helper class, focusing only on unique aspects."""

    def setUp(self):
        self.test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.test_payload_empty = Ikev1PayloadBaseTest(test_data=b'')
        self.test_payload_with_data = Ikev1PayloadBaseTest(test_data=self.test_data)

        self.test_dict_empty = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x04'),  # 4 bytes total (header only)
        ])
        self.test_bytes_empty = b''.join(self.test_dict_empty.values())

        self.test_dict_with_data = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),  # 4 + 16 = 20 bytes total
            ('test_data', self.test_data),
        ])
        self.test_bytes_with_data = b''.join(self.test_dict_with_data.values())

    def test_constructor_with_test_data(self):
        payload = Ikev1PayloadBaseTest(test_data=self.test_data)
        self.assertEqual(payload.test_data, self.test_data)
        self.assertEqual(payload.next_payload, Ikev1PayloadType.NONE)

    def test_constructor_with_empty_data(self):
        payload = Ikev1PayloadBaseTest(test_data=b'')
        self.assertEqual(payload.test_data, b'')
        self.assertEqual(payload.next_payload, Ikev1PayloadType.NONE)

    def test_get_payload_type_returns_none(self):
        self.assertEqual(Ikev1PayloadBaseTest.get_payload_type(), Ikev1PayloadType.NONE)

    def test_test_data_storage(self):
        different_data = b'\xaa\xbb\xcc\xdd'
        payload = Ikev1PayloadBaseTest(test_data=different_data)
        self.assertEqual(payload.test_data, different_data)

    def test_parse_empty_test_data(self):
        parsed: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(self.test_bytes_empty)
        self.assertEqual(parsed.test_data, b'')
        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)

    def test_parse_with_test_data(self):
        parsed: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(self.test_bytes_with_data)
        self.assertEqual(parsed.test_data, self.test_data)
        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)

    def test_compose_empty_test_data(self):
        composed_bytes = self.test_payload_empty.compose()
        self.assertEqual(composed_bytes, self.test_bytes_empty)

    def test_compose_with_test_data(self):
        composed_bytes = self.test_payload_with_data.compose()
        self.assertEqual(composed_bytes, self.test_bytes_with_data)

    def test_round_trip_test_data_preservation(self):
        composed_bytes = self.test_payload_with_data.compose()
        parsed: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(composed_bytes)
        self.assertEqual(parsed.test_data, self.test_payload_with_data.test_data)


class TestIkev1PayloadBase(unittest.TestCase):
    def setUp(self):
        self.test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.test_payload_minimal = Ikev1PayloadBaseTest(
            test_data=b'',
        )
        self.test_payload_minimal.next_payload = Ikev1PayloadType.NONE

        self.test_payload_with_data = Ikev1PayloadBaseTest(
            test_data=self.test_data
        )
        self.test_payload_with_data.next_payload = Ikev1PayloadType.KEY_EXCHANGE

        self.test_dict_minimal = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x04'),
        ])
        self.test_bytes_minimal = b''.join(self.test_dict_minimal.values())

        self.test_dict_with_data = collections.OrderedDict([
            ('next_payload', b'\x04'),  # KEY_EXCHANGE = 0x04
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),  # 4 + 16 = 20 bytes total
            ('test_data', self.test_data),
        ])
        self.test_bytes_with_data = b''.join(self.test_dict_with_data.values())

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadBaseTest.get_payload_type(), Ikev1PayloadType.NONE)

    def test_parse(self):
        parsed_minimal: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(self.test_bytes_minimal)
        self.assertEqual(parsed_minimal.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed_minimal.test_data, b'')

        parsed_with_data: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(self.test_bytes_with_data)
        self.assertEqual(parsed_with_data.next_payload, Ikev1PayloadType.KEY_EXCHANGE)
        self.assertEqual(parsed_with_data.test_data, self.test_data)

    def test_compose(self):
        composed_minimal = self.test_payload_minimal.compose()
        self.assertEqual(composed_minimal, self.test_bytes_minimal)

        composed_with_data = self.test_payload_with_data.compose()
        self.assertEqual(composed_with_data, self.test_bytes_with_data)

    def test_round_trip(self):
        composed_minimal = self.test_payload_minimal.compose()
        parsed_minimal: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(composed_minimal)

        self.assertEqual(parsed_minimal.test_data, self.test_payload_minimal.test_data)
        self.assertEqual(parsed_minimal.next_payload, self.test_payload_minimal.next_payload)

        composed_with_data = self.test_payload_with_data.compose()
        parsed_with_data: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(composed_with_data)

        self.assertEqual(parsed_with_data.test_data, self.test_payload_with_data.test_data)
        self.assertEqual(parsed_with_data.next_payload, self.test_payload_with_data.next_payload)

    def test_next_payload(self):
        self.test_payload_minimal.next_payload = Ikev1PayloadType.SECURITY_ASSOCIATION
        composed = self.test_payload_minimal.compose()
        parsed: Ikev1PayloadBaseTest = Ikev1PayloadBaseTest.parse_exact_size(composed)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.SECURITY_ASSOCIATION)

    def test_payload_length(self):
        test_data = b'\x00\x01\x02\x03\x04\x05'
        payload = Ikev1PayloadBaseTest(test_data)
        payload.next_payload = Ikev1PayloadType.NONCE

        composed = payload.compose()
        self.assertEqual(len(composed), 10)  # 1 + 1 + 2 + 6 = 10 bytes total

        self.assertEqual(composed[2:4], b'\x00\x0a')  # 10 = 0x000a

    def test_error_parse_not_enough_data(self):
        incomplete_data = self.test_bytes_minimal[:-1]

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev1PayloadBaseTest.parse_exact_size(incomplete_data)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_parse_payload_length_mismatch(self):
        malformed_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),  # 20 bytes total
        ])
        malformed_data = b''.join(malformed_dict.values())

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev1PayloadBaseTest.parse_exact_size(malformed_data)

        self.assertEqual(context_manager.exception.bytes_needed, 16)


class TestIkev1AttributeKeyLength(unittest.TestCase):
    def setUp(self):
        self.key_length_value = 128  # 128-bit key length
        self.key_length_attribute = Ikev1AttributeKeyLength(value=self.key_length_value)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeKeyLength._get_type(), Ikev1AttributeType.KEY_LENGTH)

    def test_key_length_value_support(self):
        different_key_lengths = [64, 128, 192, 256]  # bits

        for key_length in different_key_lengths:
            attribute = Ikev1AttributeKeyLength(value=key_length)
            self.assertEqual(attribute.value, key_length)

    def test_round_trip(self):
        composed_bytes = self.key_length_attribute.compose()
        parsed_attribute: Ikev1AttributeKeyLength = Ikev1AttributeKeyLength.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.key_length_attribute.value)


class TestIkev1AttributeEncryptionAlgorithm(unittest.TestCase):
    def setUp(self):
        self.encryption_algorithm = Ikev1EncryptionAlgorithm.AES_CBC
        self.encryption_attribute = Ikev1AttributeEncryptionAlgorithm(value=self.encryption_algorithm)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeEncryptionAlgorithm._get_type(), Ikev1AttributeType.ENCRYPTION_ALGORITHM)

    def test_get_enum_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeEncryptionAlgorithm._get_enum_type(), Ikev1EncryptionAlgorithm)

    def test_encryption_algorithm_support(self):
        different_encryption_algorithms = [
            Ikev1EncryptionAlgorithm.DES_CBC,
            Ikev1EncryptionAlgorithm.DES3_CBC,
            Ikev1EncryptionAlgorithm.AES_CBC,
        ]

        for encryption_algorithm in different_encryption_algorithms:
            attribute = Ikev1AttributeEncryptionAlgorithm(value=encryption_algorithm)
            self.assertEqual(attribute.value, encryption_algorithm)

    def test_round_trip(self):
        composed_bytes = self.encryption_attribute.compose()
        parsed_attribute: Ikev1AttributeEncryptionAlgorithm = Ikev1AttributeEncryptionAlgorithm.parse_exact_size(
            composed_bytes
        )

        self.assertEqual(parsed_attribute.value, self.encryption_attribute.value)


class TestIkev1AttributeAuthenticationMethod(unittest.TestCase):
    def setUp(self):
        self.auth_method = Ikev1AuthenticationMethod.PRE_SHARED_KEY
        self.auth_attribute = Ikev1AttributeAuthenticationMethod(value=self.auth_method)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeAuthenticationMethod._get_type(), Ikev1AttributeType.AUTHENTICATION_METHOD)

    def test_get_enum_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeAuthenticationMethod._get_enum_type(), Ikev1AuthenticationMethod)

    def test_authentication_method_support(self):
        different_auth_methods = [
            Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            Ikev1AuthenticationMethod.DSS_SIGNATURES,
            Ikev1AuthenticationMethod.RSA_SIGNATURES,
        ]

        for auth_method in different_auth_methods:
            attribute = Ikev1AttributeAuthenticationMethod(value=auth_method)
            self.assertEqual(attribute.value, auth_method)

    def test_round_trip(self):
        composed_bytes = self.auth_attribute.compose()
        parsed_attribute: Ikev1AttributeAuthenticationMethod = Ikev1AttributeAuthenticationMethod.parse_exact_size(
            composed_bytes
        )

        self.assertEqual(parsed_attribute.value, self.auth_attribute.value)

    def test_error_invalid_value(self):
        with self.assertRaises(InvalidValue):
            Ikev1AttributeAuthenticationMethod(value="invalid")


class TestIkev1AttributeDiffieHellmanGroup(unittest.TestCase):
    def setUp(self):
        self.dh_group = Ikev1DiffieHellmanGroup.MODP_1024_BIT
        self.dh_attribute = Ikev1AttributeDiffieHellmanGroup(value=self.dh_group)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeDiffieHellmanGroup._get_type(), Ikev1AttributeType.GROUP_DESCRIPTION)

    def test_get_enum_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeDiffieHellmanGroup._get_enum_type(), Ikev1DiffieHellmanGroup)

    def test_diffie_hellman_group_support(self):
        different_dh_groups = [
            Ikev1DiffieHellmanGroup.MODP_768_BIT,
            Ikev1DiffieHellmanGroup.MODP_1024_BIT,
            Ikev1DiffieHellmanGroup.MODP_1536_BIT,
        ]

        for dh_group in different_dh_groups:
            attribute = Ikev1AttributeDiffieHellmanGroup(value=dh_group)
            self.assertEqual(attribute.value, dh_group)

    def test_round_trip(self):
        composed_bytes = self.dh_attribute.compose()
        parsed_attribute: Ikev1AttributeDiffieHellmanGroup = Ikev1AttributeDiffieHellmanGroup.parse_exact_size(
            composed_bytes
        )

        self.assertEqual(parsed_attribute.value, self.dh_attribute.value)


class TestIkev1AttributeHashAlgorithm(unittest.TestCase):
    def setUp(self):
        self.hash_algorithm = Ikev1HashAlgorithm.MD5
        self.hash_attribute = Ikev1AttributeHashAlgorithm(value=self.hash_algorithm)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeHashAlgorithm._get_type(), Ikev1AttributeType.HASH_ALGORITHM)

    def test_get_enum_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeHashAlgorithm._get_enum_type(), Ikev1HashAlgorithm)

    def test_hash_algorithm_support(self):
        different_hash_algorithms = [
            Ikev1HashAlgorithm.MD5,
            Ikev1HashAlgorithm.SHA,
        ]

        for hash_algorithm in different_hash_algorithms:
            attribute = Ikev1AttributeHashAlgorithm(value=hash_algorithm)
            self.assertEqual(attribute.value, hash_algorithm)

    def test_round_trip(self):
        composed_bytes = self.hash_attribute.compose()
        parsed_attribute: Ikev1AttributeHashAlgorithm = Ikev1AttributeHashAlgorithm.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.hash_attribute.value)


class TestIkev1AttributeLifeType(unittest.TestCase):
    def setUp(self):
        self.life_type = Ikev1LifeType.SECONDS
        self.life_type_attribute = Ikev1AttributeLifeType(value=self.life_type)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeLifeType._get_type(), Ikev1AttributeType.LIFE_TYPE)

    def test_get_enum_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeLifeType._get_enum_type(), Ikev1LifeType)

    def test_life_type_support(self):
        different_life_types = [
            Ikev1LifeType.SECONDS,
            Ikev1LifeType.KILOBYTES,
        ]

        for life_type in different_life_types:
            attribute = Ikev1AttributeLifeType(value=life_type)
            self.assertEqual(attribute.value, life_type)

    def test_round_trip(self):
        composed_bytes = self.life_type_attribute.compose()
        parsed_attribute: Ikev1AttributeLifeType = Ikev1AttributeLifeType.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.life_type_attribute.value)


class TestIkev1AttributeLifeDuration(unittest.TestCase):
    def setUp(self):
        self.life_duration_value = 3600  # 1 hour in seconds
        self.life_duration_attribute = Ikev1AttributeLifeDuration(value=self.life_duration_value)

    def test_get_type(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeLifeDuration._get_type(), Ikev1AttributeType.LIFE_DURATION)

    def test_get_size(self):
        # pylint: disable=protected-access
        self.assertEqual(Ikev1AttributeLifeDuration._get_size(), 4)

    def test_life_duration_value_support(self):
        different_durations = [3600, 86400, 604800]  # seconds: 1 hour, 1 day, 1 week

        for duration in different_durations:
            attribute = Ikev1AttributeLifeDuration(value=duration)
            self.assertEqual(attribute.value, duration)

    def test_round_trip(self):
        composed_bytes = self.life_duration_attribute.compose()
        parsed_attribute: Ikev1AttributeLifeDuration = Ikev1AttributeLifeDuration.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_attribute.value, self.life_duration_attribute.value)


class TestIkev1PayloadTransform(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.transform_id = Ikev1TransformId.KEY_IKE
        self.attributes = []
        self.transform = Ikev1PayloadTransform(transform_id=self.transform_id, attributes=self.attributes)

        # Test data for transform without attributes
        self.test_dict_no_attrs = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x08'),
            ('transform_number', b'\x01'),  # Transform number 1
            ('transform_id', b'\x01'),  # KEY_IKE = 0x01
            ('reserved2', b'\x00\x00'),
        ])
        self.test_bytes_no_attrs = b''.join(self.test_dict_no_attrs.values())

        # Test data for transform with authentication method attribute
        self.auth_attribute = Ikev1AttributeAuthenticationMethod(value=Ikev1AuthenticationMethod.PRE_SHARED_KEY)
        self.test_dict_auth_attr = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x0c'),  # 12 bytes total
            ('transform_number', b'\x01'),  # Transform number 1
            ('transform_id', b'\x01'),  # KEY_IKE = 0x01
            ('reserved2', b'\x00\x00'),
            ('attr_format_type', b'\x80\x03'),  # AF=1, type=3 (AUTH_METHOD)
            ('attr_value', b'\x00\x01'),  # PSK = 0x0001
        ])
        self.test_bytes_auth_attr = b''.join(self.test_dict_auth_attr.values())

        # Test data for transform with key length attribute
        self.key_length_attribute = Ikev1AttributeKeyLength(value=128)
        self.test_dict_key_length_attr = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x0c'),  # 12 bytes total
            ('transform_number', b'\x01'),  # Transform number 1
            ('transform_id', b'\x01'),  # KEY_IKE = 0x01
            ('reserved2', b'\x00\x00'),
            ('attr_format_type', b'\x80\x0e'),  # AF=1, type=14 (KEY_LENGTH)
            ('attr_value', b'\x00\x80'),  # 128 = 0x0080
        ])
        self.test_bytes_key_length_attr = b''.join(self.test_dict_key_length_attr.values())

        # Test data for transform with life duration attribute
        self.life_duration_attribute = Ikev1AttributeLifeDuration(value=3600)
        self.test_dict_life_duration_attr = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x10'),  # 16 bytes total
            ('transform_number', b'\x01'),  # Transform number 1
            ('transform_id', b'\x01'),  # KEY_IKE = 0x01
            ('reserved2', b'\x00\x00'),
            ('attr_format_type', b'\x00\x0c'),  # AF=0, type=12 (LIFE_DURATION)
            ('attr_length', b'\x00\x04'),  # 4 bytes value length
            ('attr_value', b'\x00\x00\x0e\x10'),  # 3600 = 0x00000e10
        ])
        self.test_bytes_life_duration_attr = b''.join(self.test_dict_life_duration_attr.values())

        # Test data for transform with multiple attributes
        self.test_dict_multi_attrs = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x10'),  # 16 bytes total
            ('transform_number', b'\x01'),  # Transform number 1
            ('transform_id', b'\x01'),  # KEY_IKE = 0x01
            ('reserved2', b'\x00\x00'),
            ('attr1_format_type', b'\x80\x03'),  # AF=1, type=3 (AUTH_METHOD)
            ('attr1_value', b'\x00\x01'),  # PSK = 0x0001
            ('attr2_format_type', b'\x80\x0e'),  # AF=1, type=14 (KEY_LENGTH)
            ('attr2_value', b'\x00\x80'),  # 128 = 0x0080
        ])
        self.test_bytes_multi_attrs = b''.join(self.test_dict_multi_attrs.values())

        # Transform objects for compose tests
        self.transform_auth_attr = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[self.auth_attribute]
        )
        self.transform_auth_attr.transform_number = 1
        self.transform_auth_attr.next_payload = Ikev1PayloadType.NONE

        self.transform_key_length_attr = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[self.key_length_attribute]
        )
        self.transform_key_length_attr.transform_number = 1
        self.transform_key_length_attr.next_payload = Ikev1PayloadType.NONE

        self.transform_life_duration_attr = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[self.life_duration_attribute]
        )
        self.transform_life_duration_attr.transform_number = 1
        self.transform_life_duration_attr.next_payload = Ikev1PayloadType.NONE

        self.transform_multi_attrs = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[self.auth_attribute, self.key_length_attribute]
        )
        self.transform_multi_attrs.transform_number = 1
        self.transform_multi_attrs.next_payload = Ikev1PayloadType.NONE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadTransform.get_payload_type(), Ikev1PayloadType.TRANSFORM)

    def test_transform_id_storage(self):
        self.assertEqual(self.transform.transform_id, self.transform_id)

    def test_attributes_storage(self):
        self.assertEqual(self.transform.attributes, self.attributes)

    def test_transform_number_initialization(self):
        self.assertIsNone(self.transform.transform_number)

    def test_transform_with_attributes(self):
        auth_attribute = Ikev1AttributeAuthenticationMethod(value=Ikev1AuthenticationMethod.PRE_SHARED_KEY)
        transform_with_attrs = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[auth_attribute]
        )

        self.assertEqual(len(transform_with_attrs.attributes), 1)
        self.assertEqual(transform_with_attrs.attributes[0], auth_attribute)

    def test_parse(self):
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(self.test_bytes_no_attrs)

        self.assertEqual(parsed_transform.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed_transform.transform_id, Ikev1TransformId.KEY_IKE)
        self.assertEqual(len(parsed_transform.attributes), 0)

    def test_compose(self):
        self.transform.transform_number = 1
        self.transform.next_payload = Ikev1PayloadType.NONE

        composed_bytes = self.transform.compose()
        self.assertEqual(composed_bytes, self.test_bytes_no_attrs)

    def test_round_trip(self):
        self.transform.transform_number = 1
        self.transform.next_payload = Ikev1PayloadType.NONE

        composed_bytes = self.transform.compose()
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_transform.transform_id, self.transform.transform_id)
        self.assertEqual(parsed_transform.next_payload, self.transform.next_payload)
        self.assertEqual(len(parsed_transform.attributes), len(self.transform.attributes))

    def test_parse_with_attributes(self):
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(self.test_bytes_auth_attr)

        self.assertEqual(parsed_transform.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed_transform.transform_id, Ikev1TransformId.KEY_IKE)
        self.assertEqual(len(parsed_transform.attributes), 1)

        attribute = parsed_transform.attributes[0]
        self.assertIsInstance(attribute, Ikev1AttributeAuthenticationMethod)
        self.assertEqual(attribute.value, Ikev1AuthenticationMethod.PRE_SHARED_KEY)

    def test_parse_with_key_length_attribute(self):
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(
            self.test_bytes_key_length_attr
        )

        self.assertEqual(len(parsed_transform.attributes), 1)
        attribute = parsed_transform.attributes[0]
        self.assertIsInstance(attribute, Ikev1AttributeKeyLength)
        self.assertEqual(attribute.value, 128)

    def test_parse_with_life_duration_attribute(self):
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(
            self.test_bytes_life_duration_attr
        )

        self.assertEqual(len(parsed_transform.attributes), 1)
        attribute = parsed_transform.attributes[0]
        self.assertIsInstance(attribute, Ikev1AttributeLifeDuration)
        self.assertEqual(attribute.value, 3600)

    def test_compose_with_attributes(self):
        composed_bytes = self.transform_auth_attr.compose()
        self.assertEqual(composed_bytes, self.test_bytes_auth_attr)

    def test_compose_with_key_length_attribute(self):
        composed_bytes = self.transform_key_length_attr.compose()
        self.assertEqual(composed_bytes, self.test_bytes_key_length_attr)

    def test_compose_with_life_duration_attribute(self):
        composed_bytes = self.transform_life_duration_attr.compose()
        self.assertEqual(composed_bytes, self.test_bytes_life_duration_attr)

    def test_compose_with_multiple_attributes(self):
        composed_bytes = self.transform_multi_attrs.compose()
        self.assertEqual(composed_bytes, self.test_bytes_multi_attrs)

    def test_round_trip_with_attributes(self):
        composed_bytes = self.transform_multi_attrs.compose()
        parsed_transform: Ikev1PayloadTransform = Ikev1PayloadTransform.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_transform.transform_id, self.transform_multi_attrs.transform_id)
        self.assertEqual(parsed_transform.next_payload, self.transform_multi_attrs.next_payload)
        self.assertEqual(len(parsed_transform.attributes), len(self.transform_multi_attrs.attributes))

        # Verify individual attributes
        self.assertIsInstance(parsed_transform.attributes[0], Ikev1AttributeAuthenticationMethod)
        self.assertEqual(parsed_transform.attributes[0].value, Ikev1AuthenticationMethod.PRE_SHARED_KEY)
        self.assertIsInstance(parsed_transform.attributes[1], Ikev1AttributeKeyLength)
        self.assertEqual(parsed_transform.attributes[1].value, 128)


class TestIkev1PayloadKeyExchange(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.key_exchange_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.large_key_data = bytes(range(256))

        self.test_dict_small_key = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),  # 4 + 16 = 20 bytes total
            ('key_exchange_data', self.key_exchange_data),
        ])
        self.test_bytes_small_key = b''.join(self.test_dict_small_key.values())

        self.test_dict_empty_key = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x04'),
        ])
        self.test_bytes_empty_key = b''.join(self.test_dict_empty_key.values())

        self.test_dict_large_key = collections.OrderedDict([
            ('next_payload', b'\x0a'),  # NONCE = 0x0a (10)
            ('reserved', b'\x00'),
            ('payload_length', b'\x01\x04'),  # 4 + 256 = 260 bytes total
            ('key_exchange_data', self.large_key_data),
        ])
        self.test_bytes_large_key = b''.join(self.test_dict_large_key.values())

        # KE objects for compose tests
        self.ke_small = Ikev1PayloadKeyExchange(key_exchange_data=self.key_exchange_data)
        self.ke_small.next_payload = Ikev1PayloadType.NONE

        self.ke_empty = Ikev1PayloadKeyExchange(key_exchange_data=b'')
        self.ke_empty.next_payload = Ikev1PayloadType.NONE

        self.ke_large = Ikev1PayloadKeyExchange(key_exchange_data=self.large_key_data)
        self.ke_large.next_payload = Ikev1PayloadType.NONCE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadKeyExchange.get_payload_type(), Ikev1PayloadType.KEY_EXCHANGE)

    def test_constructor_with_key_data(self):
        ke = Ikev1PayloadKeyExchange(key_exchange_data=self.key_exchange_data)
        self.assertEqual(ke.key_exchange_data, self.key_exchange_data)
        self.assertEqual(ke.next_payload, Ikev1PayloadType.NONE)

    def test_constructor_with_empty_data(self):
        ke = Ikev1PayloadKeyExchange(key_exchange_data=b'')
        self.assertEqual(ke.key_exchange_data, b'')

    def test_constructor_with_large_data(self):
        ke = Ikev1PayloadKeyExchange(key_exchange_data=self.large_key_data)
        self.assertEqual(ke.key_exchange_data, self.large_key_data)
        self.assertEqual(len(ke.key_exchange_data), 256)

    def test_key_exchange_data_storage(self):
        different_data = b'\xaa\xbb\xcc\xdd\xee\xff'
        ke = Ikev1PayloadKeyExchange(key_exchange_data=different_data)
        self.assertEqual(ke.key_exchange_data, different_data)

    def test_parse_small_key_data(self):
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(self.test_bytes_small_key)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed.key_exchange_data, self.key_exchange_data)

    def test_parse_empty_key_data(self):
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(self.test_bytes_empty_key)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed.key_exchange_data, b'')

    def test_parse_large_key_data(self):
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(self.test_bytes_large_key)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONCE)
        self.assertEqual(parsed.key_exchange_data, self.large_key_data)
        self.assertEqual(len(parsed.key_exchange_data), 256)

    def test_compose_small_key_data(self):
        composed_bytes = self.ke_small.compose()
        self.assertEqual(composed_bytes, self.test_bytes_small_key)

    def test_compose_empty_key_data(self):
        composed_bytes = self.ke_empty.compose()
        self.assertEqual(composed_bytes, self.test_bytes_empty_key)

    def test_compose_large_key_data(self):
        composed_bytes = self.ke_large.compose()
        self.assertEqual(composed_bytes, self.test_bytes_large_key)

    def test_round_trip_small_key(self):
        composed_bytes = self.ke_small.compose()
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.key_exchange_data, self.ke_small.key_exchange_data)
        self.assertEqual(parsed.next_payload, self.ke_small.next_payload)

    def test_round_trip_empty_key(self):
        composed_bytes = self.ke_empty.compose()
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.key_exchange_data, self.ke_empty.key_exchange_data)
        self.assertEqual(parsed.next_payload, self.ke_empty.next_payload)

    def test_round_trip_large_key(self):
        composed_bytes = self.ke_large.compose()
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.key_exchange_data, self.ke_large.key_exchange_data)
        self.assertEqual(parsed.next_payload, self.ke_large.next_payload)
        self.assertEqual(len(parsed.key_exchange_data), len(self.ke_large.key_exchange_data))

    def test_payload_length_calculation(self):
        test_data = b'\x12\x34\x56\x78\x9a\xbc'
        ke = Ikev1PayloadKeyExchange(key_exchange_data=test_data)
        ke.next_payload = Ikev1PayloadType.VENDOR_ID

        composed = ke.compose()
        self.assertEqual(len(composed), 10)  # 4 + 6 = 10 bytes total
        self.assertEqual(composed[2:4], b'\x00\x0a')  # 10 = 0x000a

    def test_different_next_payload_types(self):
        ke = Ikev1PayloadKeyExchange(key_exchange_data=self.key_exchange_data)
        ke.next_payload = Ikev1PayloadType.SECURITY_ASSOCIATION

        composed = ke.compose()
        parsed: Ikev1PayloadKeyExchange = Ikev1PayloadKeyExchange.parse_exact_size(composed)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertEqual(parsed.key_exchange_data, self.key_exchange_data)


class TestIkev1PayloadNonce(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.nonce_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        self.large_nonce_data = bytes(range(256))

        self.test_dict_small_nonce = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),
            ('nonce_data', self.nonce_data),
        ])
        self.test_bytes_small_nonce = b''.join(self.test_dict_small_nonce.values())

        self.test_dict_empty_nonce = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x04'),
        ])
        self.test_bytes_empty_nonce = b''.join(self.test_dict_empty_nonce.values())

        self.test_dict_large_nonce = collections.OrderedDict([
            ('next_payload', b'\x04'),  # KEY_EXCHANGE = 0x04
            ('reserved', b'\x00'),
            ('payload_length', b'\x01\x04'),
            ('nonce_data', self.large_nonce_data),
        ])
        self.test_bytes_large_nonce = b''.join(self.test_dict_large_nonce.values())

        self.nonce_small = Ikev1PayloadNonce(nonce_data=self.nonce_data)
        self.nonce_small.next_payload = Ikev1PayloadType.NONE

        self.nonce_empty = Ikev1PayloadNonce(nonce_data=b'')
        self.nonce_empty.next_payload = Ikev1PayloadType.NONE

        self.nonce_large = Ikev1PayloadNonce(nonce_data=self.large_nonce_data)
        self.nonce_large.next_payload = Ikev1PayloadType.KEY_EXCHANGE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadNonce.get_payload_type(), Ikev1PayloadType.NONCE)

    def test_payload_length_calculation(self):
        test_data = b'\x12\x34\x56\x78\x9a\xbc'
        nonce = Ikev1PayloadNonce(nonce_data=test_data)
        nonce.next_payload = Ikev1PayloadType.VENDOR_ID

        composed = nonce.compose()
        self.assertEqual(len(composed), 10)
        self.assertEqual(composed[2:4], b'\x00\x0a')  # 10 = 0x000a

    def test_different_next_payload_types(self):
        nonce = Ikev1PayloadNonce(nonce_data=self.nonce_data)
        nonce.next_payload = Ikev1PayloadType.SECURITY_ASSOCIATION

        composed = nonce.compose()
        parsed: Ikev1PayloadNonce = Ikev1PayloadNonce.parse_exact_size(composed)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertEqual(parsed.nonce_data, self.nonce_data)

    def test_nonce_with_special_characters(self):
        special_nonce = b'Nonce\x00\x01\x02\x03\xff\xfe\xfd'
        nonce = Ikev1PayloadNonce(nonce_data=special_nonce)
        nonce.next_payload = Ikev1PayloadType.NOTIFICATION

        composed = nonce.compose()
        parsed: Ikev1PayloadNonce = Ikev1PayloadNonce.parse_exact_size(composed)

        self.assertEqual(parsed.nonce_data, special_nonce)
        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NOTIFICATION)
        self.assertEqual(len(parsed.nonce_data), len(special_nonce))


class TestIkev1PayloadNotification(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.doi = Ikev1Doi.IPSEC
        self.protocol_id = Ikev1ProtocolId.ISAKMP
        self.spi_size = 8
        self.notify_type = Ikev1NotifyType.NO_PROPOSAL_CHOSEN
        self.spi = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        self.notification_data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

        self.test_dict_small_notification = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x24'),  # 4 + 4 + 1 + 1 + 1 + 8 + 16 = 36 bytes total
            ('doi', b'\x00\x00\x00\x01'),  # IPSEC = 0x00000001
            ('protocol_id', b'\x01'),  # ISAKMP = 0x01
            ('spi_size', b'\x08'),
            ('notify_type', b'\x0e'),  # NO_PROPOSAL_CHOSEN = 0x0e (14)
            ('spi', b'\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('notification_data', b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
        ])
        self.test_bytes_small_notification = b''.join(self.test_dict_small_notification.values())

        self.test_dict_empty_notification = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x0c'),  # 4 + 4 + 1 + 1 + 1 + 0 + 0 = 12 bytes total
            ('doi', b'\x00\x00\x00\x00'),  # ISAKMP = 0x00000000
            ('protocol_id', b'\x01'),  # ISAKMP = 0x01
            ('spi_size', b'\x00'),
            ('notify_type', b'\x01'),  # INVALID_PAYLOAD_TYPE = 0x01
            ('spi', b''),
            ('notification_data', b''),
        ])
        self.test_bytes_empty_notification = b''.join(self.test_dict_empty_notification.values())

        self.large_spi = bytes(range(64))
        self.large_notification_data = bytes(range(128))
        self.test_dict_large_notification = collections.OrderedDict([
            ('next_payload', b'\x04'),  # KEY_EXCHANGE = 0x04
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\xcb'),  # 4 + 4 + 1 + 1 + 1 + 64 + 128 = 203 bytes total
            ('doi', b'\x00\x00\x00\x02'),  # GDOI = 0x00000002
            ('protocol_id', b'\x02'),  # IPSEC_AH = 0x02
            ('spi_size', b'\x40'),
            ('notify_type', b'\x0f'),  # BAD_PROPOSAL_SYNTAX = 0x0f
            ('spi', self.large_spi),
            ('notification_data', self.large_notification_data),
        ])
        self.test_bytes_large_notification = b''.join(self.test_dict_large_notification.values())

        # Notification objects for compose tests
        self.notification_small = Ikev1PayloadNotification(
            doi=self.doi,
            protocol_id=self.protocol_id,
            spi_size=self.spi_size,
            notify_type=self.notify_type,
            spi=self.spi,
            notification_data=self.notification_data
        )
        self.notification_small.next_payload = Ikev1PayloadType.NONE

        self.notification_empty = Ikev1PayloadNotification(
            doi=Ikev1Doi.ISAKMP,
            protocol_id=self.protocol_id,
            spi_size=0,
            notify_type=Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
            spi=b'',
            notification_data=b''
        )
        self.notification_empty.next_payload = Ikev1PayloadType.NONE

        self.notification_large = Ikev1PayloadNotification(
            doi=Ikev1Doi.GDOI,
            protocol_id=Ikev1ProtocolId.IPSEC_AH,
            spi_size=64,
            notify_type=Ikev1NotifyType.BAD_PROPOSAL_SYNTAX,
            spi=self.large_spi,
            notification_data=self.large_notification_data
        )
        self.notification_large.next_payload = Ikev1PayloadType.KEY_EXCHANGE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadNotification.get_payload_type(), Ikev1PayloadType.NOTIFICATION)

    def test_payload_length_calculation(self):
        test_spi = b'\x12\x34\x56\x78'
        test_notification_data = b'\x9a\xbc\xde\xf0'
        notification = Ikev1PayloadNotification(
            doi=Ikev1Doi.IPSEC,
            protocol_id=Ikev1ProtocolId.IPSEC_ESP,
            spi_size=4,
            notify_type=Ikev1NotifyType.INVALID_SPI,
            spi=test_spi,
            notification_data=test_notification_data
        )
        notification.next_payload = Ikev1PayloadType.VENDOR_ID

        composed = notification.compose()
        self.assertEqual(len(composed), 20)
        self.assertEqual(composed[2:4], b'\x00\x14')  # 20 = 0x0014

    def test_different_next_payload_types(self):
        notification = Ikev1PayloadNotification(
            doi=self.doi,
            protocol_id=self.protocol_id,
            spi_size=self.spi_size,
            notify_type=self.notify_type,
            spi=self.spi,
            notification_data=self.notification_data
        )
        notification.next_payload = Ikev1PayloadType.SECURITY_ASSOCIATION

        composed = notification.compose()
        parsed: Ikev1PayloadNotification = Ikev1PayloadNotification.parse_exact_size(composed)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertEqual(parsed.doi, self.doi)
        self.assertEqual(parsed.protocol_id, self.protocol_id)
        self.assertEqual(parsed.spi_size, self.spi_size)
        self.assertEqual(parsed.notify_type, self.notify_type)
        self.assertEqual(parsed.spi, self.spi)
        self.assertEqual(parsed.notification_data, self.notification_data)


class TestIkev1PayloadVendorId(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.vendor_id = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13'
        self.large_vendor_id = bytes(range(256))

        self.test_dict_small_vendor_id = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x18'),  # 4 + 20 = 24 bytes total
            ('vendor_id', self.vendor_id),
        ])
        self.test_bytes_small_vendor_id = b''.join(self.test_dict_small_vendor_id.values())

        self.test_dict_empty_vendor_id = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x04'),
        ])
        self.test_bytes_empty_vendor_id = b''.join(self.test_dict_empty_vendor_id.values())

        self.test_dict_large_vendor_id = collections.OrderedDict([
            ('next_payload', b'\x04'),  # KEY_EXCHANGE = 0x04
            ('reserved', b'\x00'),
            ('payload_length', b'\x01\x04'),  # 4 + 256 = 260 bytes total
            ('vendor_id', self.large_vendor_id),
        ])
        self.test_bytes_large_vendor_id = b''.join(self.test_dict_large_vendor_id.values())

        # Vendor ID objects for compose tests
        self.vendor_id_small = Ikev1PayloadVendorId(vendor_id=self.vendor_id)
        self.vendor_id_small.next_payload = Ikev1PayloadType.NONE

        self.vendor_id_empty = Ikev1PayloadVendorId(vendor_id=b'')
        self.vendor_id_empty.next_payload = Ikev1PayloadType.NONE

        self.vendor_id_large = Ikev1PayloadVendorId(vendor_id=self.large_vendor_id)
        self.vendor_id_large.next_payload = Ikev1PayloadType.KEY_EXCHANGE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadVendorId.get_payload_type(), Ikev1PayloadType.VENDOR_ID)

    def test_vendor_id_with_special_characters(self):
        special_vendor_id = b'Vendor\x00\x01\x02\x03\xff\xfe\xfd'
        vendor_id = Ikev1PayloadVendorId(vendor_id=special_vendor_id)
        vendor_id.next_payload = Ikev1PayloadType.NONCE

        composed = vendor_id.compose()
        parsed: Ikev1PayloadVendorId = Ikev1PayloadVendorId.parse_exact_size(composed)

        self.assertEqual(parsed.vendor_id, special_vendor_id)
        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONCE)
        self.assertEqual(len(parsed.vendor_id), len(special_vendor_id))


if __name__ == '__main__':
    unittest.main()
