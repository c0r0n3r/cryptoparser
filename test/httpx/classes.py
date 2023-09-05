# -*- coding: utf-8 -*-

import unittest


class TestCasesBasesHttpHeader:
    class MinimalHeader(unittest.TestCase):
        _header_minimal = None
        _header_minimal_bytes = None
        _header_minimal_markdown = None

        def test_parse_minimal(self):
            parsed_header = self._header_minimal.parse_exact_size(self._header_minimal_bytes)
            self.assertEqual(parsed_header, self._header_minimal)

        def test_compose_minimal(self):
            self.assertEqual(self._header_minimal.compose(), self._header_minimal_bytes)

        def test_markdown(self):
            self.assertEqual(self._header_minimal.as_markdown(), self._header_minimal_markdown)

    class FullHeaderBase(unittest.TestCase):
        _header_full = None
        _header_full_bytes = None

    class FullHeader(FullHeaderBase):
        def test_parse_full(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_bytes)
            self.assertEqual(parsed_header, self._header_full)

        def test_compose_full(self):
            self.assertEqual(self._header_full.compose(), self._header_full_bytes)

    class CaseInsensitiveHeader(FullHeaderBase):
        _header_full_upper_case_bytes = None
        _header_full_lower_case_bytes = None

        def test_parse_upper_case(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_upper_case_bytes)
            self.assertEqual(parsed_header, self._header_full)

        def test_parse_lower_case(self):
            parsed_header = self._header_full.parse_exact_size(self._header_full_lower_case_bytes)
            self.assertEqual(parsed_header, self._header_full)
