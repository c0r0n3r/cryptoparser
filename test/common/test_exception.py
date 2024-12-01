# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType, NotEnoughData, TooMuchData


class TestException(unittest.TestCase):
    def test_str(self):
        with self.assertRaisesRegex(
                NotEnoughData, 'not enough data received from target; missing_byte_count="10"'
        ) as context_manager:
            raise NotEnoughData(10)
        self.assertEqual(context_manager.exception.bytes_needed, 10)

        with self.assertRaisesRegex(
                TooMuchData, 'too much data received from target; rest_byte_count="10"'
        ) as context_manager:
            raise TooMuchData(10)
        self.assertEqual(context_manager.exception.bytes_needed, 10)

        with self.assertRaisesRegex(
                InvalidValue, '0xa is not a valid str member name value'
        ) as context_manager:
            raise InvalidValue(10, str, 'member name')
        self.assertEqual(context_manager.exception.value, 10)

        with self.assertRaisesRegex(InvalidValue, '0xa is not a valid str') as context_manager:
            raise InvalidValue(10, str)
        self.assertEqual(context_manager.exception.value, 10)

        with self.assertRaisesRegex(InvalidType, 'invalid type value received from target') as context_manager:
            raise InvalidType(10)
