#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.httpx.version import HttpVersion


class TestHttpVersion(unittest.TestCase):
    def test_markdown(self):
        self.assertEqual(HttpVersion.HTTP1_0.value.as_json(), '"http1_0"')
        self.assertEqual(HttpVersion.HTTP1_0.value.as_markdown(), 'HTTP/1.0')

        self.assertEqual(HttpVersion.HTTP1_1.value.as_json(), '"http1_1"')
        self.assertEqual(HttpVersion.HTTP1_1.value.as_markdown(), 'HTTP/1.1')
