# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import enum

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import convert_url, convert_value_to_object

from cryptoparser.common.base import StringEnumCaseInsensitiveParsable, StringEnumParsable

from cryptoparser.common.field import (
    FieldValueComponentParsable,
    FieldValueComponentParsableOptional,
    FieldValueComponentNumber,
    FieldValueComponentPercent,
    FieldValueComponentString,
    FieldValueComponentUrl,
    FieldValueStringEnumParams,
    FieldsSemicolonSeparated,
    NameValuePairListSemicolonSeparated,
)


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
