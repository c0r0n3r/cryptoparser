#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum

import attr

from cryptoparser.common.base import StringEnumParsable

from .parse import (
    HttpHeaderFieldValueMultiple,
    HttpHeaderFieldValueString,
    HttpHeaderFieldValueStringEnum,
    HttpHeaderFieldValueStringEnumParams,
    HttpHeaderFieldValueComponentMaxAge,
    HttpHeaderFieldValueComponentOption,
    HttpHeaderFieldValueComponentReportURI,
)


class HttpHeaderFieldValueComponentIncludeSubDomains(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'includeSubDomains'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)


class HttpHeaderFieldValueComponentPreload(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'preload'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)


@attr.s
class HttpHeaderFieldValueSTS(HttpHeaderFieldValueMultiple):
    max_age = attr.ib(
        converter=HttpHeaderFieldValueComponentMaxAge.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge)
    )
    include_subdomains = attr.ib(
        converter=HttpHeaderFieldValueComponentIncludeSubDomains.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentIncludeSubDomains),
        default=False
    )
    preload = attr.ib(
        converter=HttpHeaderFieldValueComponentPreload.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentPreload),
        default=False
    )


@attr.s
class HttpHeaderFieldValueExpectStaple(HttpHeaderFieldValueMultiple):
    max_age = attr.ib(
        converter=HttpHeaderFieldValueComponentMaxAge.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge)
    )
    include_subdomains = attr.ib(
        converter=HttpHeaderFieldValueComponentIncludeSubDomains.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentIncludeSubDomains),
        default=False
    )
    preload = attr.ib(
        converter=HttpHeaderFieldValueComponentPreload.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentPreload),
        default=False
    )
    report_uri = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentReportURI.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentReportURI)),
        default=None
    )


class HttpHeaderFieldValueExpectCTComponentEnforce(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'enforce'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)


@attr.s
class HttpHeaderFieldValueExpectCT(HttpHeaderFieldValueMultiple):
    max_age = attr.ib(
        converter=HttpHeaderFieldValueComponentMaxAge.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge)
    )
    enforce = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueExpectCTComponentEnforce.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueExpectCTComponentEnforce)),
        default=False
    )
    report_uri = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentReportURI.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentReportURI)),
        default=None
    )


class HttpHeaderFieldValueContentType(HttpHeaderFieldValueString):
    pass


class HttpHeaderXContentTypeOptions(StringEnumParsable, enum.Enum):
    NOSNIFF = HttpHeaderFieldValueStringEnumParams(
        code='nosniff'
    )


class HttpHeaderFieldValueXContentTypeOptions(HttpHeaderFieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXContentTypeOptions


class HttpHeaderXFrameOptions(StringEnumParsable, enum.Enum):
    DENY = HttpHeaderFieldValueStringEnumParams(
        code='DENY'
    )
    SAMEORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='SAMEORIGIN'
    )


class HttpHeaderFieldValueXFrameOptions(HttpHeaderFieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXFrameOptions


class HttpHeaderReferrerPolicy(StringEnumParsable, enum.Enum):
    NO_REFERRER = HttpHeaderFieldValueStringEnumParams(
        code='no-referrer'
    )
    NO_REFERRER_WHEN_DOWNGRADE = HttpHeaderFieldValueStringEnumParams(
        code='no-referrer-when-downgrade'
    )
    ORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='origin'
    )
    ORIGIN_WHEN_CROSS_ORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='origin-when-cross-origin'
    )
    SAME_ORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='same-origin'
    )
    STRICT_ORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='strict-origin'
    )
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN = HttpHeaderFieldValueStringEnumParams(
        code='strict-origin-when-cross-origin'
    )
    UNSAFE_URL = HttpHeaderFieldValueStringEnumParams(
        code='unsafe-url'
    )


class HttpHeaderFieldValueReferrerPolicy(HttpHeaderFieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderReferrerPolicy
