#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import collections
import unittest

from cryptodatahub.common.algorithm import Authentication, KeyExchange, NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.key import (
    PublicKey,
    PublicKeyParamsDsa,
    PublicKeyParamsEcdsa,
    PublicKeyParamsEddsa,
    PublicKeyParamsRsa,
)

from cryptodatahub.dnssec.algorithm import DnsSecAlgorithm

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.dnsrec.record import DnsRecordDnskey, DnsSecFlag, DnsSecProtocol


class TestDnsRecordDnskey(unittest.TestCase):
    def setUp(self):
        self.header_bytes = (
            b'\x01\x00' +   # flags: DNS_ZONE_KEY
            b'\x03' +       # version
            b''
        )

    def test_error_inconsistent_algorithm(self):
        public_key_rsa = PublicKey.from_params(PublicKeyParamsRsa(
            public_exponent=2 ** 2048 - 1,
            modulus=2 ** 1024 - 1,
        ))

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordDnskey(
                flags=[DnsSecFlag.DNS_ZONE_KEY],
                algorithm=DnsSecAlgorithm.DH,
                key=public_key_rsa,
                protocol=DnsSecProtocol.V3,
            )
        self.assertEqual(context_manager.exception.value, KeyExchange.DH)

        with self.assertRaises(InvalidValue) as context_manager:
            DnsRecordDnskey(
                flags=[DnsSecFlag.DNS_ZONE_KEY],
                algorithm=DnsSecAlgorithm.ECCGOST,
                key=public_key_rsa,
                protocol=DnsSecProtocol.V3,
            )
        self.assertEqual(context_manager.exception.value, Authentication.GOST_R3410_01)

    def test_error_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            DnsRecordDnskey.parse_exact_size(self.header_bytes)

        self.assertEqual(
            context_manager.exception.bytes_needed,
            DnsRecordDnskey.HEADER_SIZE - len(self.header_bytes)
        )

    def test_key_tag(self):
        record_bytes = self.header_bytes + (
            b'\x01' +            # algorithm: RSAMD5
            b'\x03' +            # exponent_length: 3
            b'\x01\x00\x01' +    # exponent: 65537
            124 * b'\x00' +      # modulus
            b'\x11\x22\x44\x88'
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.RSAMD5)
        self.assertEqual(dns_record.key_tag, 0x2244)

        record_bytes = self.header_bytes + (
            b'\x05' +          # algorithm: RSASHA1
            b'\x03' +          # exponent_length: 3
            b'\x01\x00\x01' +  # exponent: 65537
            128 * b'\xff' +    # modulus
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.RSASHA1)
        self.assertEqual(dns_record.key_tag, 1799)

    def test_asdict(self):
        self.assertEqual(
            DnsRecordDnskey(
                flags=[DnsSecFlag.DNS_ZONE_KEY],
                algorithm=DnsSecAlgorithm.RSASHA1,
                key=PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=2 ** 2048 - 1,
                    modulus=2 ** 1024 - 1,
                )),
                protocol=DnsSecProtocol.V3,
            )._asdict(),
            collections.OrderedDict([
                ('key_tag', 1540),
                ('flags', [DnsSecFlag.DNS_ZONE_KEY]),
                ('algorithm', DnsSecAlgorithm.RSASHA1),
                ('key', PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=2 ** 2048 - 1,
                    modulus=2 ** 1024 - 1,
                ))),
                ('protocol', DnsSecProtocol.V3),
            ])

        )

    def test_parse_rsa_key(self):
        record_bytes = self.header_bytes + (
            b'\x05' +          # algorithm: RSASHA1
            b'\x03' +          # exponent_length: 3
            b'\x01\x00\x01' +  # exponent: 65537
            128 * b'\xff' +    # modulus
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.RSASHA1)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsRsa(
            public_exponent=65537,
            modulus=2 ** 1024 - 1,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

        record_bytes = self.header_bytes + (
            b'\x05' +          # algorithm: RSASHA1
            b'\x00' +          # exponent length extender mark
            b'\x01\x00' +      # exponent_length: 256
            256 * b'\xff' +    # exponent
            128 * b'\xff' +    # modulus
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.RSASHA1)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsRsa(
            public_exponent=2 ** 2048 - 1,
            modulus=2 ** 1024 - 1,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

    def test_parse_dsa_key(self):
        record_bytes = self.header_bytes + (
            b'\x03' +                               # algorithm: DSA
            b'\x08' +                               # key size parameter
            20 * b'\xff' +                          # q
            b'\x80' + (1024 // 8 - 1) * b'\x00' +   # p
            b'\x40' + (1024 // 8 - 1) * b'\x00' +   # g
            b'\x20' + (1024 // 8 - 1) * b'\x00' +   # y
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.DSA)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsDsa(
            prime=2 ** 1023,
            generator=2 ** 1022,
            order=2 ** 160 - 1,
            public_key_value=2 ** 1021,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

    def test_parse_ecdsa_key(self):
        record_bytes = self.header_bytes + (
            b'\x0c' +                               # algorithm: ECCGOST
            b'\x80' + (256 // 8 - 1) * b'\x00' +     # point_x
            b'\x40' + (256 // 8 - 1) * b'\x00' +     # point_y
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.ECCGOST)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsEcdsa(
            named_group=NamedGroup.GC256B,
            point_x=2 ** 255,
            point_y=2 ** 254,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

        record_bytes = self.header_bytes + (
            b'\x0d' +                               # algorithm: ECDSAP256SHA256
            b'\x80' + (256 // 8 - 1) * b'\x00' +     # point_x
            b'\x40' + (256 // 8 - 1) * b'\x00' +     # point_y
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.ECDSAP256SHA256)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsEcdsa(
            named_group=NamedGroup.SECP256K1,
            point_x=2 ** 255,
            point_y=2 ** 254,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

        record_bytes = self.header_bytes + (
            b'\x0e' +                               # algorithm: ECDSAP384SHA384
            b'\x80' + (384 // 8 - 1) * b'\x00' +     # point_x
            b'\x40' + (384 // 8 - 1) * b'\x00' +     # point_y
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.ECDSAP384SHA384)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsEcdsa(
            named_group=NamedGroup.SECP384R1,
            point_x=2 ** 383,
            point_y=2 ** 382,
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

    def test_parse_eddsa_key(self):
        record_bytes = self.header_bytes + (
            b'\x0f' +          # algorithm: ED25519
            32 * b'\xff' +     # key_data
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.ED25519)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsEddsa(
            key_type=Authentication.ED25519,
            key_data=32 * b'\xff',
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

        record_bytes = self.header_bytes + (
            b'\x10' +          # algorithm: ED448
            56 * b'\xff' +     # key_data
            b''
        )
        dns_record = DnsRecordDnskey.parse_exact_size(record_bytes)
        self.assertEqual(dns_record.algorithm, DnsSecAlgorithm.ED448)
        self.assertEqual(dns_record.key, PublicKey.from_params(PublicKeyParamsEddsa(
            key_type=Authentication.ED448,
            key_data=56 * b'\xff',
        )))
        self.assertEqual(dns_record.compose(), record_bytes)

    def test_real(self):
        # RFC 4034 Section 5.4
        public_key_bytes = base64.b64decode(
            'AQOeiiR0GOMYkDshWoSKz9Xz'
            'fwJr1AYtsmx3TGkJaNXVbfi/'
            '2pHm822aJ5iI9BMzNXxeYCmZ'
            'DRD99WYwYqUSdjMmmAphXdvx'
            'egXd/M5+X7OrzKBaMbCVdFLU'
            'Uh6DhweJBjEVv5f2wwjM9Xzc'
            'nOf+EPbtG9DMBmADjFDc2w/r'
            'ljwvFw=='
        )
        public_key = DnsRecordDnskey.parse_key(public_key_bytes, DnsSecAlgorithm.RSASHA1)
        self.assertEqual(DnsRecordDnskey.compose_key(public_key), public_key_bytes)

        dns_record = DnsRecordDnskey(
            flags=[DnsSecFlag.DNS_ZONE_KEY],
            algorithm=DnsSecAlgorithm.RSASHA1,
            key=public_key,
            protocol=DnsSecProtocol.V3,
        )
        self.assertEqual(dns_record.key_tag, 60485)

        # RFC 4034 Section 2.3
        public_key_bytes = base64.b64decode(
            'AQPSKmynfzW4kyBv015MUG2DeIQ3'
            'Cbl+BBZH4b/0PY1kxkmvHjcZc8no'
            'kfzj31GajIQKY+5CptLr3buXA10h'
            'WqTkF7H6RfoRqXQeogmMHfpftf6z'
            'Mv1LyBUgia7za6ZEzOJBOztyvhjL'
            '742iU/TpPSEDhm2SNKLijfUppn1U'
            'aNvv4w=='
        )
        public_key = DnsRecordDnskey.parse_key(public_key_bytes, DnsSecAlgorithm.RSASHA1)
        self.assertEqual(DnsRecordDnskey.compose_key(public_key), public_key_bytes)

        dns_record = DnsRecordDnskey(
            flags=[DnsSecFlag.DNS_ZONE_KEY],
            algorithm=DnsSecAlgorithm.RSASHA1,
            key=public_key,
            protocol=DnsSecProtocol.V3,
        )
        self.assertEqual(dns_record.key_tag, 2642)

        # RFC 5702 Section 6.1
        public_key_bytes = base64.b64decode(
            'AwEAAcFcGsaxxdgiuuGmCkVI'
            'my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P'
            'kxUdp6p/DlUmObdk='
        )
        public_key = DnsRecordDnskey.parse_key(public_key_bytes, DnsSecAlgorithm.RSASHA256)
        self.assertEqual(DnsRecordDnskey.compose_key(public_key), public_key_bytes)

        dns_record = DnsRecordDnskey(
            flags=[DnsSecFlag.DNS_ZONE_KEY],
            algorithm=DnsSecAlgorithm.RSASHA256,
            key=public_key,
            protocol=DnsSecProtocol.V3,
        )
        self.assertEqual(dns_record.key_tag, 9033)

        # RFC 5702 Section 6.2
        public_key_bytes = base64.b64decode(
            'AwEAAdHoNTOW+et86KuJOWRD'
            'p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD'
            'xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g'
            'pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL'
        )
        public_key = DnsRecordDnskey.parse_key(public_key_bytes, DnsSecAlgorithm.RSASHA512)
        self.assertEqual(DnsRecordDnskey.compose_key(public_key), public_key_bytes)

        dns_record = DnsRecordDnskey(
            flags=[DnsSecFlag.DNS_ZONE_KEY],
            algorithm=DnsSecAlgorithm.RSASHA512,
            key=public_key,
            protocol=DnsSecProtocol.V3,
        )
        self.assertEqual(dns_record.key_tag, 3740)

        # RFC 5933 Section 2.2
        public_key_bytes = base64.b64decode(
            'aRS/DcPWGQj2wVJydT8EcAVoC0kXn5pDVm2I'
            'MvDDPXeD32dsSKcmq8KNVzigjL4OXZTV+t/6'
            'w4X1gpNrZiC01g=='
        )
        public_key = DnsRecordDnskey.parse_key(public_key_bytes, DnsSecAlgorithm.ECCGOST)
        self.assertEqual(DnsRecordDnskey.compose_key(public_key), public_key_bytes)

        dns_record = DnsRecordDnskey(
            flags=[DnsSecFlag.DNS_ZONE_KEY],
            algorithm=DnsSecAlgorithm.ECCGOST,
            key=public_key,
            protocol=DnsSecProtocol.V3,
        )
        self.assertEqual(dns_record.key_tag, 59732)
