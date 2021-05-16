#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import collections
import enum

import six

import attr

from cryptoparser.common.base import (
    ListParamParsable,
    ListParsable,
    Serializable,
    StringEnumCaseInsensitiveParsable,
    VariantParsable,
)
from cryptoparser.common.exception import InvalidType, InvalidValue
from cryptoparser.common.parse import ParserText, ParsableBase, ParserCRLF, ComposerText
from cryptoparser.common.utils import get_leaf_classes

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


class HttpHeaderXContentTypeOptions(StringEnumCaseInsensitiveParsable, enum.Enum):
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


class HttpHeaderXFrameOptions(StringEnumCaseInsensitiveParsable, enum.Enum):
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


class HttpHeaderReferrerPolicy(StringEnumCaseInsensitiveParsable, enum.Enum):
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


@attr.s(frozen=True)
class HttpHeaderFieldNameParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))
    normalized_name = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def _as_markdown(self, level):
        return self._markdown_result(self.normalized_name, level)


class HttpHeaderFieldName(StringEnumCaseInsensitiveParsable, enum.Enum):
    AGE = HttpHeaderFieldNameParams(
        code='age',
        normalized_name='Age'
    )
    CACHE_CONTROL = HttpHeaderFieldNameParams(
        code='cache-control',
        normalized_name='Cache-Control'
    )
    CONTENT_TYPE = HttpHeaderFieldNameParams(
        code='content-type',
        normalized_name='Content-Type'
    )
    DATE = HttpHeaderFieldNameParams(
        code='date',
        normalized_name='Date'
    )
    ETAG = HttpHeaderFieldNameParams(
        code='etag',
        normalized_name='ETag'
    )
    EXPECT_CT = HttpHeaderFieldNameParams(
        code='expect-ct',
        normalized_name='Expect-CT'
    )
    EXPECT_STAPLE = HttpHeaderFieldNameParams(
        code='expect-staple',
        normalized_name='Expect-Staple'
    )
    EXPIRES = HttpHeaderFieldNameParams(
        code='expires',
        normalized_name='Expires'
    )
    LAST_MODIFIED = HttpHeaderFieldNameParams(
        code='last-modified',
        normalized_name='Last-Modified'
    )
    PRAGMA = HttpHeaderFieldNameParams(
        code='pragma',
        normalized_name='Pragma'
    )
    SERVER = HttpHeaderFieldNameParams(
        code='server',
        normalized_name='Server'
    )
    REFERRER_POLICY = HttpHeaderFieldNameParams(
        code='referrer-policy',
        normalized_name='Referrer-Policy'
    )
    STRICT_TRANSPORT_SECURITY = HttpHeaderFieldNameParams(
        code='strict-transport-security',
        normalized_name='Strict-Transport-Security'
    )
    X_CONTENT_TYPE_OPTIONS = HttpHeaderFieldNameParams(
        code='x-content-type-options',
        normalized_name='X-Content-Type-Options'
    )
    X_FRAME_OPTIONS = HttpHeaderFieldNameParams(
        code='x-frame-options',
        normalized_name='X-Frame-Options'
    )

    @classmethod
    def from_name(cls, name):
        found_items = [
            item
            for item in cls
            if item.value.code == name.lower()
        ]

        if len(found_items) != 1:
            raise InvalidValue(name, cls, 'name')

        return found_items[0]


class HttpHeaderFieldBase(ParsableBase):
    _SEPARATOR = ': '

    @classmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _parse_name_and_separators(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator('name', ':')
        parser.parse_separator(':')
        parser.parse_separator(' ', min_length=0, max_length=None)

        return parser

    @staticmethod
    def _compose_name_and_value(name, value):
        composer = ComposerText()

        composer.compose_string_array([name, value], HttpHeaderFieldBase._SEPARATOR)

        return composer.composed


@attr.s
class HttpHeaderFieldParsedBase(HttpHeaderFieldBase):
    value = attr.ib()

    @value.validator
    def _x_validator(self, attribute, value):  # pylint: disable=unused-argument
        value_class = self._get_value_class()
        if not isinstance(value, value_class):
            self.value = value_class(value)

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_name_and_separators(parsable)
        parser.parse_string_until_separator('value', ['\r\n', ])

        if parser['name'].lower() != cls.get_canonical_name().value.code:
            raise InvalidType()

        value = cls._get_value_class().parse_exact_size(parser['value'].encode('ascii'))

        return cls(value), parser.parsed_length

    def compose(self):
        return self._compose_name_and_value(
            self.get_canonical_name().value.normalized_name,
            self.value.compose().decode('ascii')
        )

    def _asdict(self):
        return collections.OrderedDict([
            ('name', self.get_canonical_name()),
            ('value', self.value)
        ])


class HttpHeaderFieldETag(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.ETAG

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueETag


class HttpHeaderFieldAge(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.AGE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueAge


class HttpHeaderFieldContentType(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.CONTENT_TYPE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueContentType


class HttpHeaderFieldCacheControlResponse(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.CACHE_CONTROL

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueCacheControlResponse


class HttpHeaderFieldDate(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.DATE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueDate


class HttpHeaderFieldExpires(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.EXPIRES

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpires


class HttpHeaderFieldLastModified(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.LAST_MODIFIED

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueLastModified


class HttpHeaderFieldSTS(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueSTS


class HttpHeaderFieldExpectCT(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.EXPECT_CT

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpectCT


class HttpHeaderFieldExpectStaple(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.EXPECT_STAPLE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpectStaple


class HttpHeaderFieldPragma(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.PRAGMA

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValuePragma


class HttpHeaderFieldReferrerPolicy(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.REFERRER_POLICY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueReferrerPolicy


class HttpHeaderFieldServer(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.SERVER

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueServer


class HttpHeaderFieldXContentTypeOptions(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.X_CONTENT_TYPE_OPTIONS

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueXContentTypeOptions


class HttpHeaderFieldXFrameOptions(HttpHeaderFieldParsedBase):
    @classmethod
    def get_canonical_name(cls):
        return HttpHeaderFieldName.X_FRAME_OPTIONS

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueXFrameOptions


class HttpHeaderFieldParsedVariant(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (header_class.get_canonical_name(), [header_class, ])
            for header_class in get_leaf_classes(HttpHeaderFieldParsedBase)
        ])


@attr.s
class HttpHeaderFieldUnparsed(HttpHeaderFieldBase, Serializable):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_name_and_separators(parsable)
        parser.parse_string_until_separator('value', '\r\n')

        return HttpHeaderFieldUnparsed(parser['name'], parser['value']), parser.parsed_length

    def compose(self):
        return self._compose_name_and_value(self.name, self.value)


class HttpHeaderFields(ListParsable):
    @classmethod
    def get_param(cls):
        return ListParamParsable(
            item_class=HttpHeaderFieldParsedVariant,
            fallback_class=HttpHeaderFieldUnparsed,
            separator_class=ParserCRLF
        )
