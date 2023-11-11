#!/usr/bin/env python
# pylint: disable=too-many-lines
# -*- coding: utf-8 -*-

import abc
import collections
import enum

import six

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.base import (
    ListParamParsable,
    ListParsable,
    Serializable,
    StringEnumCaseInsensitiveParsable,
    StringEnumParsable,
    VariantParsable,
)
from cryptoparser.common.field import (
    FieldParsableBase,
    FieldValueBase,
    FieldValueComponentBase,
    FieldValueComponentBool,
    FieldValueComponentFloat,
    FieldValueComponentOption,
    FieldValueComponentString,
    FieldValueComponentStringBase64,
    FieldValueComponentStringEnum,
    FieldValueComponentStringEnumOption,
    FieldValueComponentTimeDelta,
    FieldValueDateTime,
    FieldValueString,
    FieldValueStringEnum,
    FieldValueStringEnumParams,
    FieldValueTimeDelta,
    FieldsCommaSeparated,
    FieldsJson,
    FieldsSemicolonSeparated,
    NameValueVariantBase,
)
from cryptoparser.common.parse import ParserCRLF, ParserText, ComposerText
from cryptoparser.common.utils import get_leaf_classes

from .parse import (
    HttpHeaderFieldValueComponent,
    HttpHeaderFieldValueComponentExpires,
    HttpHeaderFieldValueComponentMaxAge,
    HttpHeaderFieldValueComponentReport,
    HttpHeaderFieldValueComponentReportURI,
)


class HttpHeaderFieldValueETag(FieldValueString):
    pass


class HttpHeaderFieldValueAge(FieldValueTimeDelta):
    pass


class HttpHeaderFieldValueDate(FieldValueDateTime):
    pass


class HttpHeaderFieldValueExpires(FieldValueDateTime):
    pass


class HttpHeaderFieldValueLastModified(FieldValueDateTime):
    pass


class HttpHeaderFieldValueCacheControlMaxAge(HttpHeaderFieldValueComponentMaxAge):
    @classmethod
    def get_canonical_name(cls):
        return 'max-age'


class HttpHeaderFieldValueCacheControlSMaxAge(HttpHeaderFieldValueComponentMaxAge):
    @classmethod
    def get_canonical_name(cls):
        return 's-maxage'


class HttpHeaderFieldValueCacheControlNoCache(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-cache'


class HttpHeaderFieldValueCacheControlNoStore(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-store'


class HttpHeaderFieldValueCacheControlMustRevalidate(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'must-revalidate'


class HttpHeaderFieldValueCacheControlProxyRevalidate(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'proxy-revalidate'


class HttpHeaderFieldValueCacheControlPublic(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'public'


class HttpHeaderFieldValueCacheControlPrivate(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'private'


class HttpHeaderFieldValueCacheControlNoTransform(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'no-transform'


@attr.s
class HttpHeaderFieldValueCacheControlResponse(  # pylint: disable=too-many-instance-attributes
        FieldsCommaSeparated
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


class HttpHeaderFieldValueComponentIncludeSubDomains(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'includeSubDomains'


class HttpHeaderFieldValueNetworkErrorLoggingGroup(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'report_to'


class HttpHeaderFieldValueNetworkErrorLoggingMaxAge(FieldValueComponentTimeDelta):
    @classmethod
    def get_canonical_name(cls):
        return 'max_age'


class HttpHeaderFieldValueNetworkErrorLoggingIncludeSubdomains(FieldValueComponentBool):
    @classmethod
    def get_canonical_name(cls):
        return 'include_subdomains'


class HttpHeaderFieldValueNetworkErrorLoggingSuccessFraction(FieldValueComponentFloat):
    @classmethod
    def get_canonical_name(cls):
        return 'success_fraction'


class HttpHeaderFieldValueNetworkErrorLoggingFailureFraction(FieldValueComponentFloat):
    @classmethod
    def get_canonical_name(cls):
        return 'failure_fraction'


@attr.s
class HttpHeaderFieldValueNetworkErrorLogging(FieldsJson):
    report_to = attr.ib(
        converter=HttpHeaderFieldValueNetworkErrorLoggingGroup.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueNetworkErrorLoggingGroup),
    )
    max_age = attr.ib(
        converter=HttpHeaderFieldValueNetworkErrorLoggingMaxAge.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueNetworkErrorLoggingMaxAge),
    )
    include_subdomains = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueNetworkErrorLoggingIncludeSubdomains.convert),
        validator=attr.validators.optional(attr.validators.instance_of(
            HttpHeaderFieldValueNetworkErrorLoggingIncludeSubdomains
        )),
        default=None
    )
    success_fraction = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueNetworkErrorLoggingSuccessFraction.convert),
        validator=attr.validators.optional(attr.validators.instance_of(
            HttpHeaderFieldValueNetworkErrorLoggingSuccessFraction
        )),
        default=None
    )
    failure_fraction = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueNetworkErrorLoggingFailureFraction.convert),
        validator=attr.validators.optional(attr.validators.instance_of(
            HttpHeaderFieldValueNetworkErrorLoggingFailureFraction
        )),
        default=None
    )


class HttpHeaderFieldValueComponentPreload(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'preload'


@attr.s
class HttpHeaderFieldValueSTS(FieldsSemicolonSeparated):
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
class HttpHeaderFieldValueExpectStaple(FieldsSemicolonSeparated):
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


class HttpHeaderFieldValueExpectCTComponentEnforce(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'enforce'


@attr.s
class HttpHeaderFieldValueExpectCT(FieldsCommaSeparated):
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


class MimeTypeRegistry(enum.Enum):
    APPLICATION = 'application'
    AUDIO = 'audio'
    FONT = 'font'
    EXAMPLE = 'example'
    IMAGE = 'image'
    MESSAGE = 'message'
    MODEL = 'model'
    MULTIPART = 'multipart'
    TEXT = 'text'
    VIDEO = 'video'


@attr.s
class HttpHeaderFieldValueContentTypeMimeType(FieldValueComponentBase):
    type = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        default=None,
    )
    registry = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MimeTypeRegistry)),
        default=None,
    )

    def __str__(self):
        return '{}/{}'.format(self.registry.value, self.type)

    @property
    def value(self):
        return self

    @classmethod
    def get_canonical_name(cls):
        return ''

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator('registry', '/', item_class=MimeTypeRegistry)
        parser.parse_separator('/')
        parser.parse_string_by_length('type', parser.unparsed_length)

        return HttpHeaderFieldValueContentTypeMimeType(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(str(self))

        return composer.composed

    @classmethod
    def _check_name(cls, name):
        pass


class HttpHeaderFieldValueContentTypeCharset(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'charset'


class HttpHeaderFieldValueContentTypeBoundary(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'boundary'


@attr.s
class HttpHeaderFieldValueContentType(FieldsSemicolonSeparated):
    _MIME_TYPES_REQUIRE_BOUNDARY = (MimeTypeRegistry.MESSAGE, MimeTypeRegistry.MULTIPART)

    mime_type = attr.ib(
        converter=HttpHeaderFieldValueContentTypeMimeType.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueContentTypeMimeType),
        metadata={'human_readable_name': 'MIME type'}
    )
    charset = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueContentTypeCharset.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueContentTypeCharset)),
        default=None
    )
    boundary = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueContentTypeBoundary.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueContentTypeBoundary)),
        default=None
    )

    def __attrs_post_init__(self):
        if self.mime_type.registry in self._MIME_TYPES_REQUIRE_BOUNDARY and self.boundary is None:
            raise InvalidValue(None, type(self), 'boundary')

        if self.mime_type.registry not in self._MIME_TYPES_REQUIRE_BOUNDARY and self.boundary is not None:
            raise InvalidValue(self.boundary.value, type(self), 'boundary')


class HttpHeaderXContentTypeOptions(StringEnumCaseInsensitiveParsable, enum.Enum):
    NOSNIFF = FieldValueStringEnumParams(
        code='nosniff'
    )


class HttpHeaderFieldValueXContentTypeOptions(FieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXContentTypeOptions


class HttpHeaderPragma(StringEnumCaseInsensitiveParsable, enum.Enum):
    NO_CACHE = FieldValueStringEnumParams(
        code='no-cache'
    )


class HttpHeaderFieldValuePragma(FieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderPragma


class HttpHeaderFieldValuePublicKeyPinningPin(FieldValueComponentStringBase64):
    @classmethod
    def get_canonical_name(cls):
        return 'pin-sha256'


@attr.s
class HttpHeaderFieldValuePublicKeyPinning(FieldsSemicolonSeparated):
    pin_sha256 = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValuePublicKeyPinningPin.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValuePublicKeyPinningPin)),
        metadata={'human_readable_name': 'Pin (SHA-256)'}
    )
    max_age = attr.ib(
        converter=HttpHeaderFieldValueComponentMaxAge.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge),
        default=None
    )
    include_subdomains = attr.ib(
        converter=HttpHeaderFieldValueComponentIncludeSubDomains.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueComponentIncludeSubDomains),
        default=False
    )
    report_uri = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentReportURI.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentReportURI)),
        default=None
    )


class HttpHeaderFieldValueServer(FieldValueString):
    pass


class HttpHeaderFieldValueSetCookieParamDomain(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'Domain'


class HttpHeaderFieldValueSetCookieParamPath(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'Path'


class HttpHeaderFieldValueSetCookieParamSecure(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'Secure'


class HttpHeaderFieldValueSetCookieParamHttpOnly(FieldValueComponentOption):
    @classmethod
    def get_canonical_name(cls):
        return 'HttpOnly'


class HttpHeaderSetCookieComponentSameSite(StringEnumCaseInsensitiveParsable, enum.Enum):
    STRICT = FieldValueStringEnumParams(
        code='STRICT'
    )
    LAX = FieldValueStringEnumParams(
        code='Lax'
    )
    NONE = FieldValueStringEnumParams(
        code='None'
    )


class HttpHeaderFieldValueSetCookieParamSameSite(FieldValueComponentStringEnum):
    @classmethod
    def get_canonical_name(cls):
        return 'SameSite'

    @classmethod
    def _get_value_type(cls):
        return HttpHeaderSetCookieComponentSameSite


@attr.s
class HttpHeaderFieldValueSetCookieParams(FieldsSemicolonSeparated):
    expires = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentExpires.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentExpires)),
        default=None
    )
    max_age = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentMaxAge.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge)),
        default=None
    )
    domain = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamDomain.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamDomain)),
        default=None
    )
    path = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamPath.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamPath)),
        default=None
    )
    secure = attr.ib(
        converter=HttpHeaderFieldValueSetCookieParamSecure.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamSecure),
        default=HttpHeaderFieldValueSetCookieParamSecure(False)
    )
    http_only = attr.ib(
        converter=HttpHeaderFieldValueSetCookieParamHttpOnly.convert,
        validator=attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamHttpOnly),
        default=HttpHeaderFieldValueSetCookieParamHttpOnly(False)
    )
    same_site = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamSameSite.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamSameSite)),
        default=None
    )


@attr.s
class HttpHeaderFieldValueSetCookie(FieldValueBase):  # pylint: disable=too-many-instance-attributes
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))
    expires = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentExpires.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentExpires)),
        default=None
    )
    max_age = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentMaxAge.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentMaxAge)),
        default=None
    )
    domain = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamDomain.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamDomain)),
        default=None
    )
    path = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamPath.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamPath)),
        default=None
    )
    secure = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamSecure.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamSecure)),
        default=HttpHeaderFieldValueSetCookieParamSecure(False)
    )
    http_only = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamHttpOnly.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamHttpOnly)),
        default=HttpHeaderFieldValueSetCookieParamHttpOnly(False)
    )
    same_site = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueSetCookieParamSameSite.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueSetCookieParamSameSite)),
        default=None
    )

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator('name', '=')
        parser.parse_separator('=')
        parser.parse_string_until_separator_or_end('value', '; ')

        parser.parse_separator(' ', min_length=0)
        if parser.unparsed:
            parser.parse_separator(';')
        parser.parse_separator(' ', min_length=0)

        parser.parse_parsable('params', HttpHeaderFieldValueSetCookieParams)

        attributes = {
            'name': parser['name'],
            'value': parser['value'],
        }
        params = parser['params']
        attributes.update({
            name: getattr(params, name)
            for name in attr.fields_dict(type(params))
        })

        return cls(**attributes), len(parsable)

    def compose(self):
        composer = ComposerText()

        composer.compose_parsable(HttpHeaderFieldValueComponent(self.name, self.value))

        params = {}
        for name, attribute in attr.fields_dict(type(self)).items():
            value = getattr(self, name)
            if value != attribute.default and attribute.name not in ['name', 'value', ]:
                params[name] = getattr(self, name)

        if params:
            composer.compose_separator('; ')
            composer.compose_parsable(HttpHeaderFieldValueSetCookieParams(**params))

        return composer.composed


class HttpHeaderXFrameOptions(StringEnumCaseInsensitiveParsable, enum.Enum):
    DENY = FieldValueStringEnumParams(
        code='DENY'
    )
    SAMEORIGIN = FieldValueStringEnumParams(
        code='SAMEORIGIN'
    )


class HttpHeaderFieldValueXFrameOptions(FieldValueStringEnum):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXFrameOptions


class HttpHeaderXXSSProtectionState(StringEnumParsable, enum.Enum):
    ENABLED = FieldValueStringEnumParams(
        code='1',
        human_readable_name='enabled'
    )
    DISABLED = FieldValueStringEnumParams(
        code='0',
        human_readable_name='disabled'
    )


class HttpHeaderFieldValueXXSSProtectionState(FieldValueComponentStringEnumOption):
    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXXSSProtectionState


class HttpHeaderXXSSProtectionMode(StringEnumParsable, enum.Enum):
    BLOCK = FieldValueStringEnumParams(
        code='block'
    )


class HttpHeaderFieldValueXXSSProtectionMode(FieldValueComponentStringEnum):
    @classmethod
    def get_canonical_name(cls):
        return 'mode'

    @classmethod
    def _get_value_type(cls):
        return HttpHeaderXXSSProtectionMode


@attr.s
class HttpHeaderFieldValueXXSSProtection(FieldsSemicolonSeparated):
    state = attr.ib(
        converter=HttpHeaderFieldValueXXSSProtectionState,
        validator=attr.validators.instance_of(HttpHeaderFieldValueXXSSProtectionState),
    )
    mode = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueXXSSProtectionMode.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueXXSSProtectionMode)),
        default=None
    )
    report = attr.ib(
        converter=attr.converters.optional(HttpHeaderFieldValueComponentReport.convert),
        validator=attr.validators.optional(attr.validators.instance_of(HttpHeaderFieldValueComponentReport)),
        default=None
    )


class HttpHeaderReferrerPolicy(StringEnumCaseInsensitiveParsable, enum.Enum):
    NO_REFERRER = FieldValueStringEnumParams(
        code='no-referrer'
    )
    NO_REFERRER_WHEN_DOWNGRADE = FieldValueStringEnumParams(
        code='no-referrer-when-downgrade'
    )
    ORIGIN = FieldValueStringEnumParams(
        code='origin'
    )
    ORIGIN_WHEN_CROSS_ORIGIN = FieldValueStringEnumParams(
        code='origin-when-cross-origin'
    )
    SAME_ORIGIN = FieldValueStringEnumParams(
        code='same-origin'
    )
    STRICT_ORIGIN = FieldValueStringEnumParams(
        code='strict-origin'
    )
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN = FieldValueStringEnumParams(
        code='strict-origin-when-cross-origin'
    )
    UNSAFE_URL = FieldValueStringEnumParams(
        code='unsafe-url'
    )


class HttpHeaderFieldValueReferrerPolicy(FieldValueStringEnum):
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
    NETWORK_ERROR_LOGGING = HttpHeaderFieldNameParams(
        code='nel',
        normalized_name='NEL',
    )
    PRAGMA = HttpHeaderFieldNameParams(
        code='pragma',
        normalized_name='Pragma'
    )
    PUBLIC_KEY_PINNING = HttpHeaderFieldNameParams(
        code='public-key-pinning',
        normalized_name='Public-Key-Pinning'
    )
    SERVER = HttpHeaderFieldNameParams(
        code='server',
        normalized_name='Server'
    )
    SET_COOKIE = HttpHeaderFieldNameParams(
        code='set-cookie',
        normalized_name='Set-Cookie'
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
    X_XSS_PROTECTION = HttpHeaderFieldNameParams(
        code='x-xss-protection',
        normalized_name='X-XSS-Protection'
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


class HttpHeaderFieldBase(NameValueVariantBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def get_separator(cls):
        return ':'

    @classmethod
    def _compose_name_and_separator(cls, name):
        composer = cls._compose_name(name)

        composer.compose_separator(cls.get_separator())

        return composer

    def _compose_name_and_value(self, name, value):
        composer = self._compose_name_and_separator(name)

        composer.compose_separator(' ')
        composer.compose_string(value)

        return composer.composed


@attr.s
class HttpHeaderFieldParsedBase(HttpHeaderFieldBase):
    @classmethod
    @abc.abstractmethod
    def get_header_field_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()

    @classmethod
    def get_canonical_name(cls):
        return cls.get_header_field_name().value.code

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_name_and_separator(parsable)

        parser.parse_separator(' ', min_length=0, max_length=None)
        parser.parse_string_until_separator('value', ['\r\n', ])

        value = cls._get_value_class().parse_exact_size(six.ensure_binary(parser['value'], 'ascii'))

        return cls(value), parser.parsed_length

    def compose(self):
        return self._compose_name_and_value(
            self.get_header_field_name().value.normalized_name,
            six.ensure_text(bytes(self.value.compose()), 'ascii')
        )

    def _asdict(self):
        return collections.OrderedDict([
            ('name', self.get_header_field_name().value.normalized_name),
            ('value', self.value)
        ])


class HttpHeaderFieldETag(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.ETAG

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueETag


class HttpHeaderFieldAge(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.AGE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueAge


class HttpHeaderFieldContentType(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.CONTENT_TYPE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueContentType


class HttpHeaderFieldCacheControlResponse(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.CACHE_CONTROL

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueCacheControlResponse


class HttpHeaderFieldDate(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.DATE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueDate


class HttpHeaderFieldExpires(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.EXPIRES

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpires


class HttpHeaderFieldLastModified(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.LAST_MODIFIED

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueLastModified


class HttpHeaderFieldNetworkErrorLogging(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.NETWORK_ERROR_LOGGING

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueNetworkErrorLogging


class HttpHeaderFieldSTS(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.STRICT_TRANSPORT_SECURITY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueSTS


class HttpHeaderFieldExpectCT(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.EXPECT_CT

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpectCT


class HttpHeaderFieldExpectStaple(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.EXPECT_STAPLE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueExpectStaple


class HttpHeaderFieldPragma(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.PRAGMA

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValuePragma


class HttpHeaderFieldPublicKeyPinning(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.PUBLIC_KEY_PINNING

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValuePublicKeyPinning


class HttpHeaderFieldReferrerPolicy(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.REFERRER_POLICY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueReferrerPolicy


class HttpHeaderFieldSetCookie(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.SET_COOKIE

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueSetCookie


class HttpHeaderFieldServer(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.SERVER

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueServer


class HttpHeaderFieldXContentTypeOptions(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.X_CONTENT_TYPE_OPTIONS

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueXContentTypeOptions


class HttpHeaderFieldXFrameOptions(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.X_FRAME_OPTIONS

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueXFrameOptions


class HttpHeaderFieldXXSSProtection(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.X_XSS_PROTECTION

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueXXSSProtection


class HttpHeaderFieldParsedVariant(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (header_class.get_header_field_name(), [header_class, ])
            for header_class in get_leaf_classes(HttpHeaderFieldParsedBase)
        ])


@attr.s
class HttpHeaderFieldUnparsed(FieldParsableBase, Serializable):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def get_separator(cls):
        return ':'

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_name(parsable)
        parser.parse_separator(cls.get_separator())
        parser.parse_separator(' ', min_length=0, max_length=None)
        parser.parse_string_until_separator('value', '\r\n')

        return cls(parser['name'], parser['value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string_array([self.name, self.value], self.get_separator() + ' ')

        return composer.composed


class HttpHeaderFields(ListParsable):
    @classmethod
    def get_param(cls):
        return ListParamParsable(
            item_class=HttpHeaderFieldParsedVariant,
            fallback_class=HttpHeaderFieldUnparsed,
            separator_class=ParserCRLF
        )
