#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.classes import LanguageTag


class TestLanguageTag(unittest.TestCase):
    def setUp(self):
        self.language_tag = LanguageTag('a')

    def test_error(self):
        with self.assertRaises(InvalidValue):
            self.language_tag.primary_subtag = 'a1'
        with self.assertRaises(InvalidValue):
            self.language_tag.primary_subtag = ''
        with self.assertRaises(InvalidValue):
            self.language_tag.primary_subtag = 9 * 'a'

        with self.assertRaises(InvalidValue):
            self.language_tag.subsequent_subtags = ['a1', 'a#']
        with self.assertRaises(InvalidValue):
            self.language_tag.subsequent_subtags = ['a1', 9 * 'a']

        with self.assertRaises(InvalidValue):
            LanguageTag.parse_exact_size(b'')

    def test_parse(self):
        language_tag = LanguageTag.parse_exact_size(b'a')
        self.assertEqual(language_tag.primary_subtag, 'a')
        self.assertEqual(language_tag.subsequent_subtags, [])

        language_tag = LanguageTag.parse_exact_size(b'a-b-c')
        self.assertEqual(language_tag.primary_subtag, 'a')
        self.assertEqual(language_tag.subsequent_subtags, ['b', 'c', ])

    def test_compose(self):
        self.assertEqual(LanguageTag('a').compose(), b'a')
        self.assertEqual(LanguageTag('a', []).compose(), b'a')
        self.assertEqual(LanguageTag('a', ['b', 'c', ]).compose(), b'a-b-c')
