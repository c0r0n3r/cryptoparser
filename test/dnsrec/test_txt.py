#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections

import unittest

import ipaddress

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.field import NameValuePairListSemicolonSeparated
from cryptoparser.dnsrec.txt import (
    DmarcAlignment,
    DmarcFailureReportingFormat,
    DmarcFailureReportingOption,
    DmarcPolicyOption,
    DmarcPolicyVersion,
    DmarcReportingInterval,
    DnsRecordTxtValueDmarc,
    DnsRecordTxtValueMtaSts,
    DnsRecordTxtValueSpf,
    DnsRecordTxtValueSpfDirectiveA,
    DnsRecordTxtValueSpfDirectiveAll,
    DnsRecordTxtValueSpfDirectiveExists,
    DnsRecordTxtValueSpfDirectiveInclude,
    DnsRecordTxtValueSpfDirectiveIp4,
    DnsRecordTxtValueSpfDirectiveIp6,
    DnsRecordTxtValueSpfDirectiveMx,
    DnsRecordTxtValueSpfDirectivePtr,
    DnsRecordTxtValueSpfModifierExplanation,
    DnsRecordTxtValueSpfModifierRedirect,
    DnsRecordTxtValueSpfModifierUnknown,
    DnsRecordTxtValueTlsRpt,
    MtaStsPolicyVersion,
    SpfQualifier,
    SpfVersion,
    TlsRptVersion,
)


class TestDnsRecordTxtValueDmarcReportingInterval(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            DmarcReportingInterval.parse_exact_size(b'ri=5000000000')

        self.assertEqual(context_manager.exception.value, 5000000000)


class TestDnsRecordDmarc(unittest.TestCase):
    _record_minimal = DnsRecordTxtValueDmarc(DmarcPolicyVersion.DMARC1, DmarcPolicyOption.NONE)
    _record_minimal_bytes = b'v=DMARC1;p=none'
    _record_full = DnsRecordTxtValueDmarc(
        version=DmarcPolicyVersion.DMARC1,
        policy=DmarcPolicyOption.NONE,
        alignment_dkim=DmarcAlignment.STRICT,
        alignment_aspf=DmarcAlignment.STRICT,
        failure_option=DmarcFailureReportingOption.ANY_FAILURE,
        percent=99,
        reporting_url_aggregated='mailto:dmarc-report@example.com',
        reporting_url_failure='https://example.com/dmarc/report/failure',
        reporting_format=DmarcFailureReportingFormat.AUTHENTICATION_FAILURE_REPORTING_FORMAT,
        reporting_interval=3600,
        subdomain_policy=DmarcPolicyOption.NONE,
    )
    _record_full_bytes = b'; '.join([
        b'v=DMARC1',
        b'p=none',
        b'adkim=s',
        b'aspf=s',
        b'fo=1',
        b'pct=99',
        b'rua=mailto:dmarc-report@example.com',
        b'ruf=https://example.com/dmarc/report/failure',
        b'rf=afrf',
        b'ri=3600',
        b'sp=none',
    ])

    def test_parse(self):
        self.assertEqual(DnsRecordTxtValueDmarc.parse_exact_size(self._record_minimal_bytes), self._record_minimal)
        self.assertEqual(DnsRecordTxtValueDmarc.parse_exact_size(self._record_full_bytes), self._record_full)

    def test_compose(self):
        self.assertEqual(self._record_full.compose(), self._record_full_bytes)


class TestDnsRecordMtaSts(unittest.TestCase):
    _record_minimal = DnsRecordTxtValueMtaSts(MtaStsPolicyVersion.STSV1, '20160831085700Z')
    _record_minimal_bytes = b'v=STSv1; id=20160831085700Z'
    _record_full = DnsRecordTxtValueMtaSts(
        version=MtaStsPolicyVersion.STSV1,
        identifier='20160831085700Z',
        extensions=NameValuePairListSemicolonSeparated(
            collections.OrderedDict([('extension_name', 'extension_value')])
        ),
    )
    _record_full_bytes = b'v=STSv1; id=20160831085700Z; extension_name=extension_value'

    def test_parse(self):
        self.assertEqual(DnsRecordTxtValueMtaSts.parse_exact_size(self._record_minimal_bytes), self._record_minimal)
        self.assertEqual(DnsRecordTxtValueMtaSts.parse_exact_size(self._record_full_bytes), self._record_full)

    def test_compose(self):
        self.assertEqual(self._record_minimal.compose(), self._record_minimal_bytes)
        self.assertEqual(self._record_full.compose(), self._record_full_bytes)


class TestDnsRecordTxtValueTlsRpt(unittest.TestCase):
    _record_minimal = DnsRecordTxtValueTlsRpt(TlsRptVersion.TLSRPTV1, 'https://example.com/tlsrpt/report/failure')
    _record_minimal_bytes = b'v=TLSRPTv1; rua=https://example.com/tlsrpt/report/failure'
    _record_full = DnsRecordTxtValueTlsRpt(
        version=TlsRptVersion.TLSRPTV1,
        reporting_url_aggregated='mailto:tls-report@example.com',
        extensions=NameValuePairListSemicolonSeparated(
            collections.OrderedDict([('extension_name', 'extension_value')])
        ),
    )
    _record_full_bytes = b'v=TLSRPTv1; rua=mailto:tls-report@example.com; extension_name=extension_value'

    def test_parse(self):
        self.assertEqual(DnsRecordTxtValueTlsRpt.parse_exact_size(self._record_minimal_bytes), self._record_minimal)
        self.assertEqual(DnsRecordTxtValueTlsRpt.parse_exact_size(self._record_full_bytes), self._record_full)

    def test_compose(self):
        self.assertEqual(self._record_minimal.compose(), self._record_minimal_bytes)
        self.assertEqual(self._record_full.compose(), self._record_full_bytes)


class TestDnsRecordTxtValueSpfDirective(unittest.TestCase):
    def test_parse_domain_optional(self):
        directive = DnsRecordTxtValueSpfDirectivePtr.parse_exact_size(b'ptr')
        self.assertEqual(directive.domain, None)
        self.assertEqual(directive.compose(), b'ptr')

        directive = DnsRecordTxtValueSpfDirectivePtr.parse_exact_size(b'ptr:domain')
        self.assertEqual(directive.domain.value, 'domain')
        self.assertEqual(directive.compose(), b'ptr:domain')

    def test_parse_domain_required(self):
        directive = DnsRecordTxtValueSpfDirectiveInclude.parse_exact_size(b'include:domain')
        self.assertEqual(directive.domain.value, 'domain')
        self.assertEqual(directive.compose(), b'include:domain')

    def test_parse_single_cidr_length(self):
        directive = DnsRecordTxtValueSpfDirectiveIp4.parse_exact_size(b'ip4:1.1.1.1')
        self.assertEqual(directive.ipv4_network, ipaddress.IPv4Network('1.1.1.1/32'))
        self.assertEqual(directive.compose(), b'ip4:1.1.1.1')

        directive = DnsRecordTxtValueSpfDirectiveIp4.parse_exact_size(b'ip4:1.1.1.0/24')
        self.assertEqual(directive.ipv4_network, ipaddress.IPv4Network('1.1.1.0/24'))
        self.assertEqual(directive.compose(), b'ip4:1.1.1.0/24')

        directive = DnsRecordTxtValueSpfDirectiveIp6.parse_exact_size(b'ip6:::1')
        self.assertEqual(directive.ipv6_network, ipaddress.IPv6Network('::1/128'))
        self.assertEqual(directive.compose(), b'ip6:::1')

        directive = DnsRecordTxtValueSpfDirectiveIp6.parse_exact_size(b'ip6:::1:0/120')
        self.assertEqual(directive.ipv6_network, ipaddress.IPv6Network('::1:0/120'))
        self.assertEqual(directive.compose(), b'ip6:::1:0/120')

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordTxtValueSpfDirectiveMx('example.com', ipv4_cidr_length=-1)
        self.assertEqual(context_manager.exception.value, -1)

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordTxtValueSpfDirectiveMx('example.com', ipv4_cidr_length=33)
        self.assertEqual(context_manager.exception.value, 33)

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordTxtValueSpfDirectiveMx('example.com', ipv6_cidr_length=-1)
        self.assertEqual(context_manager.exception.value, -1)

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordTxtValueSpfDirectiveMx('example.com', ipv6_cidr_length=129)
        self.assertEqual(context_manager.exception.value, 129)

    def test_parse_dual_cidr_length(self):
        directive = DnsRecordTxtValueSpfDirectiveMx.parse_exact_size(b'mx:example.com')
        self.assertEqual(directive.domain.value, 'example.com')
        self.assertEqual(directive.compose(), b'mx:example.com')

        directive = DnsRecordTxtValueSpfDirectiveMx.parse_exact_size(b'mx:example.com/24')
        self.assertEqual(directive.domain.value, 'example.com')
        self.assertEqual(directive.ipv4_cidr_length, 24)
        self.assertEqual(directive.ipv6_cidr_length, None)
        self.assertEqual(directive.compose(), b'mx:example.com/24')

        directive = DnsRecordTxtValueSpfDirectiveMx.parse_exact_size(b'mx:example.com/24/64')
        self.assertEqual(directive.domain.value, 'example.com')
        self.assertEqual(directive.ipv4_cidr_length, 24)
        self.assertEqual(directive.ipv6_cidr_length, 64)
        self.assertEqual(directive.compose(), b'mx:example.com/24/64')


class TestDnsRecordTxtValueSpf(unittest.TestCase):
    _record_minimal = DnsRecordTxtValueSpf(version=SpfVersion.SPF1, terms=[])
    _record_minimal_bytes = b'v=spf1'
    _record_full = DnsRecordTxtValueSpf(
        version=SpfVersion.SPF1,
        terms=[
            DnsRecordTxtValueSpfDirectiveExists(domain='%{ir}.%{l1r+-}._spf.%{d}'),
            DnsRecordTxtValueSpfDirectiveA('example.com', 32, 128),
            DnsRecordTxtValueSpfDirectiveMx('example.com', 32, 128),
            DnsRecordTxtValueSpfDirectivePtr('example.com'),
            DnsRecordTxtValueSpfDirectiveIp4('1.2.3.4'),
            DnsRecordTxtValueSpfDirectiveIp6('::1:2:3:4'),
            DnsRecordTxtValueSpfDirectiveInclude('_spf.example.com'),
            DnsRecordTxtValueSpfModifierRedirect('redirect.example.com'),
            DnsRecordTxtValueSpfModifierExplanation('exp.example.com'),
            DnsRecordTxtValueSpfModifierUnknown('modifier_key', 'modifier_value'),
            DnsRecordTxtValueSpfDirectiveAll(SpfQualifier.FAIL),
        ],
    )
    _record_full_bytes = b' '.join([
        b'v=spf1',
        b'exists:%{ir}.%{l1r+-}._spf.%{d}',
        b'a:example.com/32/128',
        b'mx:example.com/32/128',
        b'ptr:example.com',
        b'ip4:1.2.3.4',
        b'ip6:::1:2:3:4',
        b'include:_spf.example.com',
        b'redirect=redirect.example.com',
        b'exp=exp.example.com',
        b'modifier_key=modifier_value',
        b'-all',
    ])

    def test_error_non_spf(self):
        with self.assertRaises(InvalidType):
            DnsRecordTxtValueSpf.parse_exact_size(b'v=STSv1')

    def test_parse(self):
        self.assertEqual(DnsRecordTxtValueSpf.parse_exact_size(self._record_minimal_bytes), self._record_minimal)
        self.assertEqual(DnsRecordTxtValueSpf.parse_exact_size(self._record_full_bytes), self._record_full)

    def test_compose(self):
        self.assertEqual(self._record_minimal.compose(), self._record_minimal_bytes)
        self.assertEqual(self._record_full.compose(), self._record_full_bytes)

    def test_as_markdown(self):
        self.assertEqual(self._record_minimal.as_markdown(), '\n'.join([
            '* Version: SPF1',
            '* Terms: -',
            '',
        ]))

        self.assertEqual(self._record_full.as_markdown(), '\n'.join([
            '* Version: SPF1',
            '* Terms:',
            '    * Exists:',
            '        * Domain: %{ir}.%{l1r+-}._spf.%{d}',
            '        * Qualifier: n/a',
            '    * A/AAAA records:',
            '        * Domain: example.com',
            '        * Ipv4 Cidr Length: 32',
            '        * Ipv6 Cidr Length: 128',
            '        * Qualifier: n/a',
            '    * MX records:',
            '        * Domain: example.com',
            '        * Ipv4 Cidr Length: 32',
            '        * Ipv6 Cidr Length: 128',
            '        * Qualifier: n/a',
            '    * PTR records:',
            '        * Domain: example.com',
            '        * Qualifier: n/a',
            '    * IPv4 records:',
            '        * Ipv4 Network: 1.2.3.4/32',
            '        * Qualifier: n/a',
            '    * IPv6 records:',
            '        * Ipv6 Network: ::1:2:3:4/128',
            '        * Qualifier: n/a',
            '    * Include:',
            '        * Domain: _spf.example.com',
            '        * Qualifier: n/a',
            '    * Redirect: redirect.example.com',
            '    * Explanation: exp.example.com',
            '    * Modifier Key: modifier_value',
            '    * All:',
            '        * Qualifier: Fail',
            '',
        ]))
