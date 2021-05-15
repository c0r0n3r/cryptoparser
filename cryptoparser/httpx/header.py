#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum

import attr

from cryptoparser.common.base import StringEnumCaseInsensitiveParsable, StringEnumParsable

from .parse import (
    HttpHeaderFieldsCommaSeparated,
    HttpHeaderFieldsSemicolonSeparated,
    HttpHeaderFieldValueString,
    HttpHeaderFieldValueStringEnum,
    HttpHeaderFieldValueStringEnumParams,
    HttpHeaderFieldValueComponentMaxAge,
    HttpHeaderFieldValueComponentOption,
    HttpHeaderFieldValueComponentReportURI,
    HttpHeaderFieldValueTimeDelta,
    HttpHeaderFieldValueDateTime,
)


class HttpHeaderFieldValueETag(HttpHeaderFieldValueString):
    pass


class HttpHeaderFieldValueAge(HttpHeaderFieldValueTimeDelta):
    pass


class HttpHeaderFieldValueDate(HttpHeaderFieldValueDateTime):
    pass


class HttpHeaderFieldValueExpires(HttpHeaderFieldValueDateTime):
    pass


class HttpHeaderFieldValueLastModified(HttpHeaderFieldValueDateTime):
    pass


class HttpHeaderFieldValueCacheControlMaxAge(HttpHeaderFieldValueComponentMaxAge):
    @classmethod
    def get_canonical_name(cls):
        return 'max-age'


class HttpHeaderFieldValueCacheControlSMaxAge(HttpHeaderFieldValueComponentMaxAge):
    @classmethod
    def get_canonical_name(cls):
        return 's-maxage'


class HttpHeaderFieldValueCacheControlNoCache(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-cache'


class HttpHeaderFieldValueCacheControlNoStore(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-store'


class HttpHeaderFieldValueCacheControlMustRevalidate(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'must-revalidate'


class HttpHeaderFieldValueCacheControlProxyRevalidate(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'proxy-revalidate'


class HttpHeaderFieldValueCacheControlPublic(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'public'


class HttpHeaderFieldValueCacheControlPrivate(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'private'


class HttpHeaderFieldValueCacheControlNoTransform(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-transform'


@attr.s
class HttpHeaderFieldValueCacheControlResponse(  # pylint: disable=too-many-instance-attributes
        HttpHeaderFieldsCommaSeparated
):
    max_age = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueCacheControlMaxAge.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueCacheControlMaxAge)),
        default=None
    )
    s_maxage = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueCacheControlSMaxAge.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueCacheControlSMaxAge)),
        default=None
    )
    must_revalidate = attr.ib(
        converter=HttpHeaderFieldValueCacheControlMustRevalidate.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlMustRevalidate),
        default=False
    )
    proxy_revalidate = attr.ib(
        converter=HttpHeaderFieldValueCacheControlProxyRevalidate.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlProxyRevalidate),
        default=False
    )
    no_cache = attr.ib(
        converter=HttpHeaderFieldValueCacheControlNoCache.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlNoCache),
        default=False,
    )
    no_store = attr.ib(
        converter=HttpHeaderFieldValueCacheControlNoStore.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlNoStore),
        default=False,
    )
    public = attr.ib(
        converter=HttpHeaderFieldValueCacheControlPublic.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlPublic),
        default=False,
    )
    private = attr.ib(
        converter=HttpHeaderFieldValueCacheControlPrivate.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlPrivate),
        default=False,
    )
    no_transform = attr.ib(
        converter=HttpHeaderFieldValueCacheControlNoTransform.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueCacheControlNoTransform),
        default=False,
    )


class HttpHeaderFieldValueComponentIncludeSubDomains(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'includeSubDomains'


class HttpHeaderFieldValueComponentPreload(HttpHeaderFieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'preload'


@attr.s
class HttpHeaderFieldValueSTS(HttpHeaderFieldsSemicolonSeparated):
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
class HttpHeaderFieldValueExpectStaple(HttpHeaderFieldsSemicolonSeparated):
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


@attr.s
class HttpHeaderFieldValueExpectCT(HttpHeaderFieldsCommaSeparated):
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


class HttpHeaderPragma(StringEnumCaseInsensitiveParsable, enum.Enum):
    NO_CACHE = HttpHeaderFieldValueStringEnumParams(
        code='no-cache'
    )


class HttpHeaderFieldValuePragma(HttpHeaderFieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderPragma


class HttpHeaderFieldValueServer(HttpHeaderFieldValueString):
    pass


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
