#!/usr/bin/env python
# pylint: disable=too-many-lines
# -*- coding: utf-8 -*-

import abc
import collections
import itertools
import enum

import six

import attr
import urllib3

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import (
    Base64Data,
    CryptoDataParamsEnumString,
    convert_base64_data,
    convert_iterable,
    convert_url,
    convert_value_to_object,
)

from cryptoparser.common.base import (
    ListParamParsable,
    ListParsable,
    Serializable,
    StringEnumCaseInsensitiveParsable,
    StringEnumParsable,
    VariantParsable,
    VariantParsableExact,
)
from cryptoparser.common.exception import InvalidType
from cryptoparser.common.field import (
    FieldParsableBase,
    FieldValueBase,
    FieldValueComponentBool,
    FieldValueComponentFloat,
    FieldValueComponentOption,
    FieldValueComponentString,
    FieldValueComponentStringBase64,
    FieldValueComponentStringEnum,
    FieldValueComponentStringEnumOption,
    FieldValueComponentTimeDelta,
    FieldValueDateTime,
    FieldValueMimeType,
    FieldValueString,
    FieldValueStringBySeparatorBase,
    FieldValueStringEnum,
    FieldValueStringEnumParams,
    FieldValueTimeDelta,
    FieldsCommaSeparated,
    FieldsJson,
    FieldsSemicolonSeparated,
    MimeTypeRegistry,
    NameValueVariantBase,
)
from cryptoparser.common.parse import ParsableBase, ParserCRLF, ParserText, ComposerText
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


class ContentSecurityPolicyDirectiveType(StringEnumParsable, enum.Enum):
    BASE_URI = FieldValueStringEnumParams(
        code='base-uri',
    )
    BLOCK_ALL_MIXED_CONTENT = FieldValueStringEnumParams(
        code='block-all-mixed-content',
    )
    CHILD_SRC = FieldValueStringEnumParams(
        code='child-src',
    )
    CONNECT_SRC = FieldValueStringEnumParams(
        code='connect-src',
    )
    DEFAULT_SRC = FieldValueStringEnumParams(
        code='default-src',
    )
    FONT_SRC = FieldValueStringEnumParams(
        code='font-src',
    )
    FORM_ACTION = FieldValueStringEnumParams(
        code='form-action',
    )
    FRAME_ANCESTORS = FieldValueStringEnumParams(
        code='frame-ancestors',
    )
    FRAME_SRC = FieldValueStringEnumParams(
        code='frame-src',
    )
    IMG_SRC = FieldValueStringEnumParams(
        code='img-src',
    )
    MANIFEST_SRC = FieldValueStringEnumParams(
        code='manifest-src',
    )
    MEDIA_SRC = FieldValueStringEnumParams(
        code='media-src',
    )
    OBJECT_SRC = FieldValueStringEnumParams(
        code='object-src',
    )
    PLUGIN_TYPES = FieldValueStringEnumParams(
        code='plugin-types',
    )
    PREFETCH_SRC = FieldValueStringEnumParams(
        code='prefetch-src',
    )
    REFERRER = FieldValueStringEnumParams(
        code='referrer',
    )
    REPORT_SAMPLE = FieldValueStringEnumParams(
        code='report-sample',
    )
    REPORT_TO = FieldValueStringEnumParams(
        code='report-to',
    )
    REPORT_URI = FieldValueStringEnumParams(
        code='report-uri',
    )
    REQUIRE_TRUSTED_TYPES_FOR = FieldValueStringEnumParams(
        code='require-trusted-types-for',
    )
    SANDBOX = FieldValueStringEnumParams(
        code='sandbox',
    )
    SCRIPT_SRC = FieldValueStringEnumParams(
        code='script-src',
    )
    SCRIPT_SRC_ATTR = FieldValueStringEnumParams(
        code='script-src-attr',
    )
    SCRIPT_SRC_ELEM = FieldValueStringEnumParams(
        code='script-src-elem',
    )
    STYLE_SRC = FieldValueStringEnumParams(
        code='style-src',
    )
    STYLE_SRC_ATTR = FieldValueStringEnumParams(
        code='style-src-attr',
    )
    STYLE_SRC_ELEM = FieldValueStringEnumParams(
        code='style-src-elem',
    )
    TRUSTED_TYPES = FieldValueStringEnumParams(
        code='trusted-types',
    )
    UNSAFE_HASHES = FieldValueStringEnumParams(
        code='unsafe-hashes',
    )
    UPGRADE_INSECURE_REQUESTS = FieldValueStringEnumParams(
        code='upgrade-insecure-requests',
    )
    WEBRTC = FieldValueStringEnumParams(
        code='webrtc',
    )
    WORKER_SRC = FieldValueStringEnumParams(
        code='worker-src',
    )


ContentSecurityPolicySourceType = enum.Enum('ContentSecurityPolicySourceType', 'SCHEME HOST KEYWORD NONCE HASH')


class FieldHashTypeParams(CryptoDataParamsEnumString):
    pass


class StringEnumHashParsableBase(StringEnumParsable):
    @classmethod
    def from_hash_algorithm(cls, hash_algorithm):
        return cls[hash_algorithm.name]

    @property
    def hash_algorithm(self):
        return Hash[self.name]  # pylint: disable=no-member


class ContentSecurityPolicySourceHashType(StringEnumHashParsableBase, enum.Enum):
    SHA2_256 = FieldHashTypeParams(code='sha256')
    SHA2_384 = FieldHashTypeParams(code='sha384')
    SHA2_512 = FieldHashTypeParams(code='sha512')


@attr.s
class ContentSecurityPolicySourceHash(ParsableBase, Serializable):
    hash_algorithm = attr.ib(validator=attr.validators.instance_of((Hash, six.string_types)))
    hash_value = attr.ib(converter=convert_base64_data(), validator=attr.validators.instance_of(Base64Data))

    @classmethod
    def _get_hash_algorithm_enum_type(cls):
        return ContentSecurityPolicySourceHashType

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_parsable('hash_algorithm', cls._get_hash_algorithm_enum_type())
        except InvalidValue as e:
            six.raise_from(InvalidType(), e)

        parser.parse_string_until_separator_or_end('hash_value', ' ')

        return cls(parser['hash_algorithm'].hash_algorithm, parser['hash_value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(
            self._get_hash_algorithm_enum_type().from_hash_algorithm(self.hash_algorithm).value.code
        )
        composer.compose_separator('-')
        composer.compose_string(str(self.hash_value))

        return composer.composed

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicySourceType.HASH


@attr.s
class ContentSecurityPolicySourceNonce(ParsableBase, Serializable):
    _PREFIX = 'nonce-'

    value = attr.ib(converter=convert_base64_data(), validator=attr.validators.instance_of(Base64Data))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_string('prefix', cls._PREFIX)
        except InvalidValue as e:
            six.raise_from(InvalidType(), e)

        del parser['prefix']

        parser.parse_string_until_separator_or_end('value', ' ')

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self._PREFIX)
        composer.compose_string(str(self.value))

        return composer.composed

    def _asdict(self):
        return self.value

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicySourceType.NONCE


@attr.s
class ContentSecurityPolicySourceScheme(ParsableBase, Serializable):
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator('value', ':')
        parser.parse_separator(':')

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value)
        composer.compose_separator(':')

        return composer.composed

    def _asdict(self):
        return self.value

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicySourceType.SCHEME


@attr.s
class ContentSecurityPolicySourceHost(ParsableBase, Serializable):
    value = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(six.string_types + (urllib3.util.url.Url, ))
    )

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator_or_end('value', ' ')

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value)

        return composer.composed

    def _asdict(self):
        return self.value

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicySourceType.HOST


class ContentSecurityPolicySourceKeyword(StringEnumParsable, enum.Enum):
    NONE = FieldValueStringEnumParams(code='\'none\'')
    REPORT_SAMPLE = FieldValueStringEnumParams(code='\'report-sample\'')
    SELF = FieldValueStringEnumParams(code='\'self\'')
    STRICT_DYNAMIC = FieldValueStringEnumParams(code='\'strict-dynamic\'')
    UNSAFE_ALLOW_REDIRECTS = FieldValueStringEnumParams(code='\'unsafe-allow-redirects\'')
    UNSAFE_EVAL = FieldValueStringEnumParams(code='\'unsafe-eval\'')
    UNSAFE_HASHES = FieldValueStringEnumParams(code='\'unsafe-hashes\'')
    UNSAFE_INLINE = FieldValueStringEnumParams(code='\'unsafe-inline\'')
    WASM_UNSAFE_EVAL = FieldValueStringEnumParams(code='\'wasm-unsafe-eval\'')

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicySourceType.KEYWORD


@attr.s
class ContentSecurityPolicyDirectiveBase(ParsableBase, Serializable):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_type(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_parsable('type', ContentSecurityPolicyDirectiveType)
        if parser['type'] != cls.get_type():
            raise InvalidType()

        return parser

    def _compose_type(self):
        composer = ComposerText()

        composer.compose_string(self.get_type())

        return composer


class ContentSecurityPolicySerializedSource(VariantParsableExact):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (ContentSecurityPolicySourceType.KEYWORD, [ContentSecurityPolicySourceKeyword]),
            (ContentSecurityPolicySourceType.NONCE, [ContentSecurityPolicySourceNonce]),
            (ContentSecurityPolicySourceType.HASH, [ContentSecurityPolicySourceHash]),
            (ContentSecurityPolicySourceType.SCHEME, [ContentSecurityPolicySourceScheme]),
            (ContentSecurityPolicySourceType.HOST, [ContentSecurityPolicySourceHost]),
        ])


@attr.s
class ContentSecurityPolicyDirectiveSourceBase(ContentSecurityPolicyDirectiveBase):
    value = attr.ib()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_source_parser(cls):
        raise NotImplementedError()

    @value.validator
    def value_validator(self, _, value):
        self._value_validator(value)

    def _value_validator(self, value):
        source_variant_parsable = self._get_source_parser()
        acceptable_source_types = tuple(itertools.chain.from_iterable(
            source_variant_parsable._get_variants().values()  # pylint: disable=protected-access
        ))
        has_invalid_source_type = any(map(
            lambda source: not isinstance(source, acceptable_source_types),
            value
        ))
        if has_invalid_source_type:
            raise InvalidValue(value, type(self), 'value')

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_type(parsable)

        source_variant_parsable = cls._get_source_parser()

        if parser.unparsed_length:
            parser.parse_separator(' ')
            parser.parse_string_array('value', ' ', source_variant_parsable, skip_empty=True)
            directive_value = parser['value']
        else:
            raise InvalidValue(parser.unparsed, cls, 'value')

        return cls(directive_value), parser.parsed_length

    def compose(self):
        composer = self._compose_type()

        if self.value:
            composer.compose_separator(' ')
            composer.compose_string_array(self.value, ' ')

        return composer.composed

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('value', [
                collections.OrderedDict([('type', source.get_type()), ('value', source._asdict())])
                for source in self.value
            ])
        ])


class ContentSecurityPolicyDirectiveSerializedSourceListBase(ContentSecurityPolicyDirectiveSourceBase):
    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _get_source_parser(cls):
        return ContentSecurityPolicySerializedSource


class ContentSecurityPolicyDirectiveChildSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.CHILD_SRC


class ContentSecurityPolicyDirectiveConnectSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.CONNECT_SRC


class ContentSecurityPolicyDirectiveDefaultSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.DEFAULT_SRC


class ContentSecurityPolicyDirectiveFontSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.FONT_SRC


class ContentSecurityPolicyDirectiveFrameSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.FRAME_SRC


class ContentSecurityPolicyDirectiveImgSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.IMG_SRC


class ContentSecurityPolicyDirectiveManifestSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.MANIFEST_SRC


class ContentSecurityPolicyDirectiveMediaSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.MEDIA_SRC


class ContentSecurityPolicyDirectiveObjectSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.OBJECT_SRC


class ContentSecurityPolicyDirectivePrefetchSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.PREFETCH_SRC


class ContentSecurityPolicyDirectiveScriptSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.SCRIPT_SRC


class ContentSecurityPolicyDirectiveScriptSrcAttr(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.SCRIPT_SRC_ATTR


class ContentSecurityPolicyDirectiveScriptSrcElem(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.SCRIPT_SRC_ELEM


class ContentSecurityPolicyDirectiveStyleSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.STYLE_SRC


class ContentSecurityPolicyDirectiveStyleSrcAttr(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.STYLE_SRC_ATTR


class ContentSecurityPolicyDirectiveStyleSrcElem(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.STYLE_SRC_ELEM


class ContentSecurityPolicyDirectiveWorkerSrc(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.WORKER_SRC


class ContentSecurityPolicyDirectiveBaseUri(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.BASE_URI


class ContentSecurityPolicyDirectiveFormAction(ContentSecurityPolicyDirectiveSerializedSourceListBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.FORM_ACTION


class ContentSecurityPolicyFrameAncestorsSource(VariantParsableExact):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (ContentSecurityPolicySourceType.KEYWORD, [ContentSecurityPolicySourceKeyword]),
            (ContentSecurityPolicySourceType.SCHEME, [ContentSecurityPolicySourceScheme]),
            (ContentSecurityPolicySourceType.HOST, [ContentSecurityPolicySourceHost]),
        ])


class ContentSecurityPolicyDirectiveFrameAncestors(ContentSecurityPolicyDirectiveSourceBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.FRAME_ANCESTORS

    @classmethod
    def _get_source_parser(cls):
        return ContentSecurityPolicyFrameAncestorsSource

    def _value_validator(self, value):
        super(ContentSecurityPolicyDirectiveFrameAncestors, self)._value_validator(value)

        has_invalid_source_type = any(map(
            lambda source: (
                isinstance(source, ContentSecurityPolicySourceKeyword) and
                source not in [ContentSecurityPolicySourceKeyword.SELF, ContentSecurityPolicySourceKeyword.NONE]
            ),
            value
        ))
        if has_invalid_source_type:
            raise InvalidValue(value, type(self), 'value')


class ContentSecurityPolicyDirectiveVariant(VariantParsableExact):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (directive_class.get_type(), [directive_class, ])
            for directive_class in get_leaf_classes(ContentSecurityPolicyDirectiveBase)
        ])


@attr.s
class ContentSecurityPolicyDirectiveValueBase(ContentSecurityPolicyDirectiveBase):
    value = attr.ib()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()

    @value.validator
    def _value_validator(self, _, value):
        if not isinstance(value, self._get_value_class()):
            raise InvalidValue(value, type(self), 'value')

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_type(parsable)

        parser.parse_separator(' ')
        parser.parse_parsable('value', cls._get_value_class())

        return cls(parser['value']), parser.parsed_length

    def compose(self):
        composer = self._compose_type()

        composer.compose_separator(' ')
        composer.compose_parsable(self.value)

        return composer.composed

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


class ContentSecurityPolicyWebRtcType(StringEnumParsable, enum.Enum):
    ALLOW = FieldValueStringEnumParams(code='\'allow\'')
    BLOCK = FieldValueStringEnumParams(code='\'block\'')


class ContentSecurityPolicyDirectiveWebrtc(ContentSecurityPolicyDirectiveValueBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.WEBRTC

    @classmethod
    def _get_value_class(cls):
        return ContentSecurityPolicyWebRtcType


class ContentSecurityPolicyReferrerPolicy(StringEnumParsable, enum.Enum):
    NO_REFERRER = FieldValueStringEnumParams(code='"no-referrer"')
    NON_WHEN_DOWNGRADE = FieldValueStringEnumParams(code='"non-when-downgrade"')
    ORIGIN = FieldValueStringEnumParams(code='"origin"')
    ORIGIN_WHEN_CROSSORIGIN = FieldValueStringEnumParams(code='"origin-when-crossorigin"')
    ORIGIN_WHEN_CROSS_ORIGIN = FieldValueStringEnumParams(code='"origin-when-cross-origin"')
    UNSAFE_URL = FieldValueStringEnumParams(code='"unsafe-url"')


class ContentSecurityPolicyDirectiveReferrer(ContentSecurityPolicyDirectiveValueBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.REFERRER

    @classmethod
    def _get_value_class(cls):
        return ContentSecurityPolicyReferrerPolicy


class ContentSecurityPolicyReportUri(FieldValueStringBySeparatorBase):
    @classmethod
    def _get_separators(cls):
        return ' "<>^`{|}'


class ContentSecurityPolicyToken(FieldValueStringBySeparatorBase):
    @classmethod
    def _get_separators(cls):
        return '"(),/:;<=>?@[\\]{} \t'


class ContentSecurityPolicyDirectiveListValueBase(ContentSecurityPolicyDirectiveBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_by_value_params(cls, parsable, value_type, value_name, value_min_length=None):
        parser = cls._parse_type(parsable)

        if parser.unparsed_length:
            parser.parse_separator(' ')
            parser.parse_string_array('value', ' ', value_type, skip_empty=True)

        if value_min_length is not None and ('value' not in parser or len(parser['value']) < value_min_length):
            raise InvalidValue(parser.unparsed, cls, value_name)

        return cls(parser['value']), parser.parsed_length

    def _compose(self, value_name):
        composer = self._compose_type()

        value = getattr(self, value_name)
        if value:
            composer.compose_separator(' ')
            composer.compose_parsable_array(value, ' ')

        return composer.composed


@attr.s
class ContentSecurityPolicyDirectiveSandbox(ContentSecurityPolicyDirectiveListValueBase):
    tokens = attr.ib(
        converter=convert_iterable(convert_value_to_object(ContentSecurityPolicyToken)),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(ContentSecurityPolicyToken)
        )
    )

    @classmethod
    def _parse(cls, parsable):
        return cls._parse_by_value_params(parsable, ContentSecurityPolicyToken, 'tokens')

    def compose(self):
        return self._compose('tokens')

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.SANDBOX

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('tokens', self.tokens),
        ])


@attr.s
class ContentSecurityPolicyDirectivePluginTypes(ContentSecurityPolicyDirectiveListValueBase):
    mime_types = attr.ib(
        converter=convert_iterable(convert_value_to_object(FieldValueMimeType)),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(FieldValueMimeType)
        ),
        metadata={'human_readable_name': 'MIME Types'}
    )

    @classmethod
    def _parse(cls, parsable):
        return cls._parse_by_value_params(parsable, FieldValueMimeType, 'mime_types')

    def compose(self):
        return self._compose('mime_types')

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.PLUGIN_TYPES

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('mime_types', self.mime_types),
        ])


class ContentSecurityPolicyTrustedTypeSinkGroup(StringEnumParsable, enum.Enum):
    SCRIPT = FieldValueStringEnumParams(code='\'script\'')


@attr.s
class ContentSecurityPolicyDirectiveRequireTrustedTypesFor(ContentSecurityPolicyDirectiveListValueBase):
    sink_groups = attr.ib(
        converter=convert_iterable(convert_value_to_object(ContentSecurityPolicyTrustedTypeSinkGroup)),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(ContentSecurityPolicyTrustedTypeSinkGroup)
        ),
    )

    @classmethod
    def _parse(cls, parsable):
        return cls._parse_by_value_params(parsable, ContentSecurityPolicyTrustedTypeSinkGroup, 'sink_groups')

    def compose(self):
        return self._compose('sink_groups')

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.REQUIRE_TRUSTED_TYPES_FOR

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('sink_groups', self.sink_groups),
        ])


@attr.s
class ContentSecurityPolicyDirectiveReportUri(ContentSecurityPolicyDirectiveListValueBase):
    uri_references = attr.ib(
        converter=convert_iterable(convert_value_to_object(ContentSecurityPolicyReportUri)),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(ContentSecurityPolicyReportUri),
        ),
        metadata={'human_readable_name': 'URI references'}
    )

    @classmethod
    def _parse(cls, parsable):
        return cls._parse_by_value_params(parsable, ContentSecurityPolicyReportUri, 'uri_references', 1)

    def compose(self):
        return self._compose('uri_references')

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.REPORT_URI

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('uri_references', self.uri_references),
        ])


@attr.s
class ContentSecurityPolicyDirectiveReportTo(ContentSecurityPolicyDirectiveBase):
    token = attr.ib(
        converter=convert_value_to_object(ContentSecurityPolicyToken),
        validator=attr.validators.instance_of(ContentSecurityPolicyToken)
    )

    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.REPORT_TO

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_type(parsable)

        parser.parse_separator(' ')
        parser.parse_parsable('token', ContentSecurityPolicyToken)

        return cls(parser['token']), parser.parsed_length

    def compose(self):
        composer = self._compose_type()

        composer.compose_separator(' ')
        composer.compose_parsable(self.token)

        return composer.composed


class ContentSecurityPolicyDirectiveNoValueBase(ContentSecurityPolicyDirectiveBase):
    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_type(parsable)

        return cls(), parser.parsed_length

    def compose(self):
        composer = self._compose_type()

        return composer.composed

    def _asdict(self):
        return collections.OrderedDict([
            ('type', self.get_type()),
            ('value', None),
        ])


class ContentSecurityPolicyDirectiveBlockAllMixedContent(ContentSecurityPolicyDirectiveNoValueBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.BLOCK_ALL_MIXED_CONTENT


class ContentSecurityPolicyDirectiveUpgradeInsecureRequests(ContentSecurityPolicyDirectiveNoValueBase):
    @classmethod
    def get_type(cls):
        return ContentSecurityPolicyDirectiveType.UPGRADE_INSECURE_REQUESTS


@attr.s
class HttpHeaderFieldValueContentSecurityPolicy(ParsableBase, Serializable):
    directives = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(ContentSecurityPolicyDirectiveBase)
        )
    )

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_array(
            'directives',
            separator=';',
            item_class=ContentSecurityPolicyDirectiveVariant,
            separator_spaces=' ',
            skip_empty=True,
        )

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string_array(self.directives, '; ')

        return composer.composed


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
        converter=FieldValueMimeType.convert,
        validator=attr.validators.instance_of(FieldValueMimeType),
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
    CONTENT_SECURITY_POLICY = HttpHeaderFieldNameParams(
        code='content-security-policy',
        normalized_name='Content-Security-Policy'
    )
    CONTENT_SECURITY_POLICY_REPORT_ONLY = HttpHeaderFieldNameParams(
        code='content-security-policy-report-only',
        normalized_name='Content-Security-Policy-Report-Only'
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
    X_CONTENT_SECURITY_POLICY = HttpHeaderFieldNameParams(
        code='x-content-security-policy',
        normalized_name='X-Content-Security-Policy'
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


class HttpHeaderFieldContentSecurityPolicy(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.CONTENT_SECURITY_POLICY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueContentSecurityPolicy


class HttpHeaderFieldXContentSecurityPolicy(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.X_CONTENT_SECURITY_POLICY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueContentSecurityPolicy


class HttpHeaderFieldContentSecurityPolicyReportOnly(HttpHeaderFieldParsedBase):
    @classmethod
    def get_header_field_name(cls):
        return HttpHeaderFieldName.CONTENT_SECURITY_POLICY_REPORT_ONLY

    @classmethod
    def _get_value_class(cls):
        return HttpHeaderFieldValueContentSecurityPolicy


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
