# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import collections
import enum
import ipaddress

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import convert_url, convert_value_to_object

from cryptoparser.common.base import (
    Serializable,
    StringEnumCaseInsensitiveParsable,
    StringEnumParsable,
    VariantParsable
)
from cryptoparser.common.exception import InvalidType

from cryptoparser.common.field import (
    FieldValueComponentParsable,
    FieldValueComponentParsableOptional,
    FieldValueComponentNumber,
    FieldValueComponentPercent,
    FieldValueComponentString,
    FieldValueComponentUrl,
    FieldValueSingleBase,
    FieldValueStringEnumParams,
    FieldsSemicolonSeparated,
    NameValuePairListSemicolonSeparated,
    NameValuePair,
)
from cryptoparser.common.parse import ComposerText, ParsableBase, ParserText


class DmarcAlignment(StringEnumCaseInsensitiveParsable, enum.Enum):
    RELAXED = FieldValueStringEnumParams(
        code='r',
        human_readable_name='Relaxed',
    )
    STRICT = FieldValueStringEnumParams(
        code='s',
        human_readable_name='Strict',
    )


class DmarcIdentifierAlignmentBase(FieldValueComponentParsable):
    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _get_value_class(cls):
        return DmarcAlignment


class DnsRecordTxtValueDmarcValueIdentifierAlignmentDkim(DmarcIdentifierAlignmentBase):
    @classmethod
    def get_canonical_name(cls):
        return 'adkim'


class DnsRecordTxtValueDmarcValueIdentifierAlignmentAspf(DmarcIdentifierAlignmentBase):
    @classmethod
    def get_canonical_name(cls):
        return 'aspf'


class DmarcPolicyOption(StringEnumCaseInsensitiveParsable, enum.Enum):
    NONE = FieldValueStringEnumParams(
        code='none'
    )
    QUARANTINE = FieldValueStringEnumParams(
        code='quarantine'
    )
    REJECT = FieldValueStringEnumParams(
        code='reject'
    )


class DnsRecordTxtValueDmarcValuePolicy(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'p'

    @classmethod
    def _get_value_class(cls):
        return DmarcPolicyOption


class DnsRecordTxtValueDmarcValueSubdomainPolicy(FieldValueComponentParsableOptional):
    @classmethod
    def get_canonical_name(cls):
        return 'sp'

    @classmethod
    def _get_value_class(cls):
        return DmarcPolicyOption


class DmarcPolicyVersion(StringEnumParsable, enum.Enum):
    DMARC1 = FieldValueStringEnumParams(
        code='DMARC1',
        human_readable_name='DMARC1',
    )


class DnsRecordTxtValueDmarcValueVersion(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'v'

    @classmethod
    def _get_value_class(cls):
        return DmarcPolicyVersion


class DmarcFailureReportingOption(StringEnumCaseInsensitiveParsable, enum.Enum):
    ALL_FAILURE = FieldValueStringEnumParams(
        code='0',
        human_readable_name='All Failure',
    )
    ANY_FAILURE = FieldValueStringEnumParams(
        code='1',
        human_readable_name='Any Failure',
    )
    DKIM_FAILURE = FieldValueStringEnumParams(
        code='d',
        human_readable_name='DKIM Failure',
    )
    SPF_FAILURE = FieldValueStringEnumParams(
        code='s',
        human_readable_name='SPF Failure',
    )


class DmarcValueFailureOption(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'fo'

    @classmethod
    def _get_value_class(cls):
        return DmarcFailureReportingOption


class DnsRecordTxtValueDmarcValuePercent(FieldValueComponentPercent):
    @classmethod
    def get_canonical_name(cls):
        return 'pct'


@attr.s
class DmarcReportingInterval(FieldValueComponentNumber):
    def __attrs_post_init__(self):
        if self.value < 0 or self.value >= 2 ** 32:
            raise InvalidValue(self.value, type(self), 'value')

    @classmethod
    def get_canonical_name(cls):
        return 'ri'


class DmarcFailureReportingFormat(StringEnumCaseInsensitiveParsable, enum.Enum):
    AUTHENTICATION_FAILURE_REPORTING_FORMAT = FieldValueStringEnumParams(
        code='afrf',
        human_readable_name='Authentication Failure Reporting Format (AFRF)',
    )


class DmarcReportingFormat(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'rf'

    @classmethod
    def _get_value_class(cls):
        return DmarcFailureReportingFormat


class DnsRecordTxtValueDmarcValueReportingUrlAggregated(FieldValueComponentUrl):
    @classmethod
    def get_canonical_name(cls):
        return 'rua'


class DnsRecordTxtValueDmarcValueReportingUrlFailure(FieldValueComponentUrl):
    @classmethod
    def get_canonical_name(cls):
        return 'ruf'


@attr.s
class DnsRecordTxtValueDmarc(FieldsSemicolonSeparated):  # pylint: disable=too-many-instance-attributes
    version = attr.ib(
        converter=DnsRecordTxtValueDmarcValueVersion.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueDmarcValueVersion)
    )
    policy = attr.ib(
        converter=DnsRecordTxtValueDmarcValuePolicy.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueDmarcValuePolicy)
    )
    alignment_dkim = attr.ib(
        default=DmarcAlignment.RELAXED,
        converter=DnsRecordTxtValueDmarcValueIdentifierAlignmentDkim.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueDmarcValueIdentifierAlignmentDkim),
        metadata={'human_readable_name': 'DKIM Alignment'},
    )
    alignment_aspf = attr.ib(
        default=DmarcAlignment.RELAXED,
        converter=DnsRecordTxtValueDmarcValueIdentifierAlignmentAspf.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueDmarcValueIdentifierAlignmentAspf),
        metadata={'human_readable_name': 'ASPF Alignment'},
    )
    failure_option = attr.ib(
        default=DmarcFailureReportingOption.ALL_FAILURE,
        converter=DmarcValueFailureOption.convert,
        validator=attr.validators.instance_of(DmarcValueFailureOption),
    )
    percent = attr.ib(
        default=100,
        converter=DnsRecordTxtValueDmarcValuePercent.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueDmarcValuePercent),
    )
    reporting_url_aggregated = attr.ib(
        default=None,
        converter=convert_value_to_object(DnsRecordTxtValueDmarcValueReportingUrlAggregated, convert_url()),
        validator=attr.validators.optional(
            attr.validators.instance_of(DnsRecordTxtValueDmarcValueReportingUrlAggregated)
        ),
        metadata={'human_readable_name': 'Aggregated Reporting URL'},
    )
    reporting_url_failure = attr.ib(
        default=None,
        converter=convert_value_to_object(DnsRecordTxtValueDmarcValueReportingUrlFailure, convert_url()),
        validator=attr.validators.optional(attr.validators.instance_of(DnsRecordTxtValueDmarcValueReportingUrlFailure)),
        metadata={'human_readable_name': 'Failure Reporting URL'},
    )
    reporting_format = attr.ib(
        default=DmarcFailureReportingFormat.AUTHENTICATION_FAILURE_REPORTING_FORMAT,
        converter=DmarcReportingFormat.convert,
        validator=attr.validators.instance_of(DmarcReportingFormat),
    )
    reporting_interval = attr.ib(
        default=86400,
        converter=DmarcReportingInterval.convert,
        validator=attr.validators.instance_of(DmarcReportingInterval),
    )
    subdomain_policy = attr.ib(
        default=None,
        converter=DnsRecordTxtValueDmarcValueSubdomainPolicy.convert,
        validator=attr.validators.optional(attr.validators.instance_of(DnsRecordTxtValueDmarcValueSubdomainPolicy))
    )


class MtaStsPolicyVersion(StringEnumParsable, enum.Enum):
    STSV1 = FieldValueStringEnumParams(
        code='STSv1',
        human_readable_name='STSv1',
    )


class DnsRecordMtaStsValueVersion(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'v'

    @classmethod
    def _get_value_class(cls):
        return MtaStsPolicyVersion


class DnsRecordMtaStsValueId(FieldValueComponentString):
    @classmethod
    def get_canonical_name(cls):
        return 'id'


@attr.s
class DnsRecordTxtValueMtaSts(FieldsSemicolonSeparated):
    version = attr.ib(
        converter=DnsRecordMtaStsValueVersion.convert,
        validator=attr.validators.instance_of(DnsRecordMtaStsValueVersion)
    )
    identifier = attr.ib(
        converter=DnsRecordMtaStsValueId.convert,
        validator=attr.validators.instance_of(DnsRecordMtaStsValueId)
    )
    extensions = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(NameValuePairListSemicolonSeparated)),
        metadata={'extension': True},
    )


class TlsRptVersion(StringEnumParsable, enum.Enum):
    TLSRPTV1 = FieldValueStringEnumParams(
        code='TLSRPTv1',
        human_readable_name='TLSRPTv1',
    )


class DnsRecordTxtValueTlsRptValueVersion(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'v'

    @classmethod
    def _get_value_class(cls):
        return TlsRptVersion


class DnsRecordTxtValueTlsRptValueReportingUrlAggregated(FieldValueComponentUrl):
    @classmethod
    def get_canonical_name(cls):
        return 'rua'


@attr.s
class DnsRecordTxtValueTlsRpt(FieldsSemicolonSeparated):
    version = attr.ib(
        converter=DnsRecordTxtValueTlsRptValueVersion.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueTlsRptValueVersion)
    )
    reporting_url_aggregated = attr.ib(
        default=None,
        converter=DnsRecordTxtValueTlsRptValueReportingUrlAggregated.convert,
        validator=attr.validators.optional(
            attr.validators.instance_of(DnsRecordTxtValueTlsRptValueReportingUrlAggregated)
        ),
    )
    extensions = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(NameValuePairListSemicolonSeparated)),
        metadata={'extension': True},
    )


class SpfVersion(StringEnumParsable, enum.Enum):
    SPF1 = FieldValueStringEnumParams(
        code='spf1',
        human_readable_name='SPF1',
    )


class DnsRecordTxtValueSpfVersion(FieldValueComponentParsable):
    @classmethod
    def get_canonical_name(cls):
        return 'v'

    @classmethod
    def _get_value_class(cls):
        return SpfVersion


class SpfQualifier(StringEnumParsable, enum.Enum):
    PASS = FieldValueStringEnumParams(
        code='+',
        human_readable_name='Pass',
    )
    FAIL = FieldValueStringEnumParams(
        code='-',
        human_readable_name='Fail',
    )
    SOFTFAIL = FieldValueStringEnumParams(
        code='~',
        human_readable_name='Softfail',
    )
    NEUTRAL = FieldValueStringEnumParams(
        code='?',
        human_readable_name='Neutral',
    )


class SpfMechanism(StringEnumParsable, enum.Enum):
    ALL = FieldValueStringEnumParams(
        code='all',
        human_readable_name='All',
    )
    INCLUDE = FieldValueStringEnumParams(
        code='include',
        human_readable_name='Include',
    )
    A = FieldValueStringEnumParams(
        code='a',
        human_readable_name='A/AAAA records',
    )
    MX = FieldValueStringEnumParams(
        code='mx',
        human_readable_name='MX records',
    )
    PTR = FieldValueStringEnumParams(
        code='ptr',
        human_readable_name='PTR records',
    )
    IP4 = FieldValueStringEnumParams(
        code='ip4',
        human_readable_name='IPv4 records',
    )
    IP6 = FieldValueStringEnumParams(
        code='ip6',
        human_readable_name='IPv6 records',
    )
    EXISTS = FieldValueStringEnumParams(
        code='exists',
        human_readable_name='Exists',
    )


class SpfModifier(StringEnumParsable, enum.Enum):
    REDIRECT = FieldValueStringEnumParams(
        code='redirect',
        human_readable_name='Redirect',
    )
    EXP = FieldValueStringEnumParams(
        code='exp',
        human_readable_name='Explanation',
    )


@attr.s
class SpfDomainSpec(FieldValueSingleBase):
    @classmethod
    def _get_value_type(cls):
        return str

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator_or_end('value', separators=' ')

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value)

        return composer.composed


class DnsRecordTxtValueSpfModifierKnownBase(FieldValueComponentParsable):
    @classmethod
    @abc.abstractmethod
    def get_modifier(cls):
        raise NotImplementedError()

    @classmethod
    def get_canonical_name(cls):
        return cls.get_modifier().value.code

    @classmethod
    def _get_value_class(cls):
        return SpfDomainSpec


class DnsRecordTxtValueSpfModifierRedirect(DnsRecordTxtValueSpfModifierKnownBase):
    @classmethod
    def get_modifier(cls):
        return SpfModifier.REDIRECT


class DnsRecordTxtValueSpfModifierExplanation(DnsRecordTxtValueSpfModifierKnownBase):
    @classmethod
    def get_modifier(cls):
        return SpfModifier.EXP


class DnsRecordTxtValueSpfModifierUnknown(NameValuePair):
    pass


class DnsRecordTxtValueSpfDirectiveBase(ParsableBase, Serializable):
    @classmethod
    @abc.abstractmethod
    def get_mechanism(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_qualifier_and_mechanism_name(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_parsable('qualifier', SpfQualifier)
        except InvalidValue:
            pass

        mechanism = cls.get_mechanism()
        try:
            parser.parse_string('mechanism', mechanism.value.code)
        except InvalidValue as e:
            raise InvalidType from e

        return parser

    @classmethod
    def _parse_domain(cls, parser, optional, extra_separators=''):
        has_separator = True
        if optional:
            try:
                parser.parse_separator(':', min_length=1, max_length=1)
            except InvalidValue:
                has_separator = False
        else:
            parser.parse_separator(':', min_length=1, max_length=1)

        if has_separator:
            parser.parse_string_until_separator_or_end('domain', separators=' ' + extra_separators)

        return parser.get('domain', None)

    @classmethod
    def _compose_domain(cls, composer, domain):
        if domain is None:
            return

        composer.compose_separator(':')
        composer.compose_string(domain)

    @classmethod
    def _parse_ip_network(cls, parser):
        parser.parse_string('separator', ':')
        parser.parse_string_until_separator_or_end('ip_network', ' ')

        return parser['ip_network']

    @classmethod
    def _compose_ip_network(cls, composer, ip_network):
        composer.compose_separator(':')
        composer.compose_string(str(ip_network.network_address))
        if ip_network.prefixlen != ip_network.max_prefixlen:
            composer.compose_separator('/')
            composer.compose_numeric(ip_network.prefixlen)

    @classmethod
    def _parse_ip_cidr_length(cls, parser):
        has_separator = True
        try:
            parser.parse_separator('/', min_length=1, max_length=1)
        except InvalidValue:
            has_separator = False

        if has_separator:
            parser.parse_numeric('ip_cidr_length')
            ip_cidr_length = parser['ip_cidr_length']
            del parser['ip_cidr_length']
        else:
            ip_cidr_length = None

        return ip_cidr_length

    @classmethod
    def _compose_ip_cidr_length(cls, composer, ip_cidr_length):
        if ip_cidr_length is None:
            return

        composer.compose_separator('/')
        composer.compose_numeric(ip_cidr_length)

    def _compose_qualifier_and_mechanism_name(self, qualifier):
        composer = ComposerText()

        if qualifier is not None:
            composer.compose_string(qualifier.value.code)

        composer.compose_string(self.get_mechanism().value.code)

        return composer


@attr.s
class DnsRecordTxtValueSpfDirectiveAll(DnsRecordTxtValueSpfDirectiveBase):
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier))
    )

    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.ALL

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        return cls(qualifier=parser.get('qualifier', None)), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        return composer.composed


@attr.s
class DnsRecordTxtValueSpfDirectiveDomain(DnsRecordTxtValueSpfDirectiveBase):
    domain = attr.ib(
        converter=SpfDomainSpec.convert,
        validator=attr.validators.instance_of(SpfDomainSpec)
    )
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier))
    )

    @classmethod
    @abc.abstractmethod
    def get_mechanism(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        qualifier = parser.get('qualifier', None)
        domain = cls._parse_domain(parser, False)

        return cls(qualifier=qualifier, domain=domain), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        self._compose_domain(composer, self.domain)

        return composer.composed


@attr.s
class DnsRecordTxtValueSpfDirectivePtr(DnsRecordTxtValueSpfDirectiveBase):
    domain = attr.ib(
        default=None,
        converter=SpfDomainSpec.convert,
        validator=attr.validators.optional(attr.validators.instance_of(SpfDomainSpec)),
    )
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier)),
    )

    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.PTR

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        qualifier = parser.get('qualifier', None)
        domain = cls._parse_domain(parser, True)

        return cls(qualifier=qualifier, domain=domain), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        self._compose_domain(composer, self.domain)

        return composer.composed


@attr.s
class DnsRecordTxtValueSpfDirectiveDomainCidr(DnsRecordTxtValueSpfDirectiveBase):
    domain = attr.ib(
        default=None,
        converter=SpfDomainSpec.convert,
        validator=attr.validators.optional(attr.validators.instance_of(SpfDomainSpec)),
    )
    ipv4_cidr_length = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    ipv6_cidr_length = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier)),
    )

    @classmethod
    @abc.abstractmethod
    def get_mechanism(cls):
        raise NotImplementedError()

    @ipv4_cidr_length.validator
    def _validator_ipv4_cidr_length(self, attribute, value):  # pylint: disable=unused-argument
        if value is None:
            return

        if value < 0 or value > 32:
            raise InvalidValue(value, type(self), 'ipv4_cidr_length')

    @ipv6_cidr_length.validator
    def _validator_ipv6_cidr_length(self, attribute, value):  # pylint: disable=unused-argument
        if value is None:
            return

        if value < 0 or value > 128:
            raise InvalidValue(value, type(self), 'ipv6_cidr_length')

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        qualifier = parser.get('qualifier', None)
        domain = cls._parse_domain(parser, True, extra_separators='/')
        ipv4_cidr_length = cls._parse_ip_cidr_length(parser)
        ipv6_cidr_length = cls._parse_ip_cidr_length(parser)

        return cls(
            qualifier=qualifier,
            domain=domain,
            ipv4_cidr_length=ipv4_cidr_length,
            ipv6_cidr_length=ipv6_cidr_length
        ), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        self._compose_domain(composer, self.domain)
        self._compose_ip_cidr_length(composer, self.ipv4_cidr_length)
        self._compose_ip_cidr_length(composer, self.ipv6_cidr_length)

        return composer.composed


class DnsRecordTxtValueSpfDirectiveInclude(DnsRecordTxtValueSpfDirectiveDomain):
    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.INCLUDE


class DnsRecordTxtValueSpfDirectiveA(DnsRecordTxtValueSpfDirectiveDomainCidr):
    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.A


class DnsRecordTxtValueSpfDirectiveMx(DnsRecordTxtValueSpfDirectiveDomainCidr):
    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.MX


@attr.s
class DnsRecordTxtValueSpfDirectiveIp4(DnsRecordTxtValueSpfDirectiveBase):
    ipv4_network = attr.ib(
        converter=ipaddress.ip_network,
        validator=attr.validators.instance_of(ipaddress.IPv4Network)
    )
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier)),
    )

    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.IP4

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        qualifier = parser.get('qualifier', None)
        ipv4_network = cls._parse_ip_network(parser)

        return cls(
            qualifier=qualifier,
            ipv4_network=ipv4_network,
        ), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        self._compose_ip_network(composer, self.ipv4_network)

        return composer.composed


@attr.s
class DnsRecordTxtValueSpfDirectiveIp6(DnsRecordTxtValueSpfDirectiveBase):
    ipv6_network = attr.ib(
        converter=ipaddress.ip_network,
        validator=attr.validators.instance_of(ipaddress.IPv6Network)
    )
    qualifier = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(SpfQualifier)),
    )

    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.IP6

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_qualifier_and_mechanism_name(parsable)

        qualifier = parser.get('qualifier', None)
        ipv6_network = cls._parse_ip_network(parser)

        return cls(
            qualifier=qualifier,
            ipv6_network=ipv6_network,
        ), parser.parsed_length

    def compose(self):
        composer = self._compose_qualifier_and_mechanism_name(self.qualifier)

        self._compose_ip_network(composer, self.ipv6_network)

        return composer.composed


class DnsRecordTxtValueSpfDirectiveExists(DnsRecordTxtValueSpfDirectiveDomain):
    @classmethod
    def get_mechanism(cls):
        return SpfMechanism.EXISTS


class DnsRecordTxtValueSpfVariantParsable(VariantParsable):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (SpfMechanism.ALL, [DnsRecordTxtValueSpfDirectiveAll, ]),
            (SpfMechanism.INCLUDE, [DnsRecordTxtValueSpfDirectiveInclude, ]),
            (SpfMechanism.A, [DnsRecordTxtValueSpfDirectiveA, ]),
            (SpfMechanism.MX, [DnsRecordTxtValueSpfDirectiveMx, ]),
            (SpfMechanism.PTR, [DnsRecordTxtValueSpfDirectivePtr, ]),
            (SpfMechanism.IP4, [DnsRecordTxtValueSpfDirectiveIp4, ]),
            (SpfMechanism.IP6, [DnsRecordTxtValueSpfDirectiveIp6, ]),
            (SpfMechanism.EXISTS, [DnsRecordTxtValueSpfDirectiveExists, ]),
            (SpfModifier.REDIRECT, [DnsRecordTxtValueSpfModifierRedirect, ]),
            (SpfModifier.EXP, [DnsRecordTxtValueSpfModifierExplanation, ]),
        ])


@attr.s
class DnsRecordTxtValueSpf(ParsableBase, Serializable):
    terms = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of((
            DnsRecordTxtValueSpfDirectiveBase,
            DnsRecordTxtValueSpfModifierKnownBase,
            DnsRecordTxtValueSpfModifierUnknown,
        )))
    )
    version = attr.ib(
        default=DnsRecordTxtValueSpfVersion(SpfVersion.SPF1),
        converter=DnsRecordTxtValueSpfVersion.convert,
        validator=attr.validators.instance_of(DnsRecordTxtValueSpfVersion)
    )

    def _asdict(self):
        terms = []
        for term in self.terms:
            if isinstance(term, DnsRecordTxtValueSpfModifierKnownBase):
                terms.append((term.get_modifier(), term.value.value))
            elif isinstance(term, DnsRecordTxtValueSpfDirectiveBase):
                terms.append((term.get_mechanism(), term._asdict()))
            elif isinstance(term, DnsRecordTxtValueSpfModifierUnknown):
                terms.append((term.name, term.value))
            else:
                raise NotImplementedError()

        return collections.OrderedDict([
            ('Version', self.version),
            ('Terms', collections.OrderedDict(terms)),
        ])

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_parsable('version', DnsRecordTxtValueSpfVersion)
        except InvalidValue as e:
            raise InvalidType from e

        terms = []
        while parser.unparsed_length:
            parser.parse_separator(' ')

            try:
                parser.parse_parsable('term', DnsRecordTxtValueSpfVariantParsable)
                term = parser['term']
            except InvalidValue:
                parser.parse_string_until_separator_or_end('term', ' ')
                term_parser = ParserText(parser['term'].encode('ascii'))
                term_parser.parse_parsable('value', DnsRecordTxtValueSpfModifierUnknown)
                term = term_parser['value']

            terms.append(term)
            del parser['term']

        return cls(version=parser['version'], terms=terms), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_parsable(self.version)

        for term in self.terms:
            composer.compose_separator(' ')
            composer.compose_parsable(term)

        return composer.composed
