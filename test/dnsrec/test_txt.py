#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.dnsrec.txt import (
    DmarcAlignment,
    DmarcFailureReportingFormat,
    DmarcFailureReportingOption,
    DmarcPolicyVersion,
    DmarcPolicyOption,
    DnsRecordTxtValueDmarc,
    DmarcReportingInterval,
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
