#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import unittest

from tests.common.classes import JSONSerializableEnum, JSONSerializableStringEnum, JSONSerializableObject


class TestJSONSerializable(unittest.TestCase):
    def test_serialize_enum(self):
        self.assertEqual(json.dumps(JSONSerializableEnum.first), '{"first": {"code": 1}}')

        self.assertEqual(repr(JSONSerializableObject(1)), '{\"value\": 1}')
        self.assertEqual(json.dumps(JSONSerializableObject(1)), '"{\\\"value\\\": 1}"')
