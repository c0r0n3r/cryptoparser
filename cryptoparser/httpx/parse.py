#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.field import (
    FieldValueComponentQuotedString,
    FieldValueComponentTimeDelta,
    NameValuePair,
)


class HttpHeaderFieldValueComponent(NameValuePair):
    pass


class HttpHeaderFieldValueComponentMaxAge(FieldValueComponentTimeDelta):
    @classmethod
    def get_canonical_name(cls):
        return 'max-age'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)


class HttpHeaderFieldValueComponentReportURI(FieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'report-uri'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)
