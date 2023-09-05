#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections

import unittest

from cryptodatahub.common.exception import InvalidValue

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
    DnsRecordTxtValueTlsRpt,
    MtaStsPolicyVersion,
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
