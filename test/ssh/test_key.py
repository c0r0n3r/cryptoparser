#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import collections
import datetime
import ipaddress
import unittest

from collections import OrderedDict

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import Authentication, Hash, NamedGroup
from cryptodatahub.common.key import (
    PublicKey,
    PublicKeySize,
    PublicKeyParamsDsa,
    PublicKeyParamsEcdsa,
    PublicKeyParamsEddsa,
    PublicKeyParamsRsa,
)
from cryptodatahub.common.exception import InvalidValue

from cryptodatahub.ssh.algorithm import SshHostKeyAlgorithm

from cryptoparser.common.exception import InvalidType, NotEnoughData

from cryptoparser.ssh.key import (
    SshCertType,
    SshCertExtensionVector,
    SshCertExtensionForceCommand,
    SshCertExtensionNoPrecenseRequired,
    SshCertExtensionPermitX11Forwarding,
    SshCertExtensionPermitAgentForwarding,
    SshCertExtensionPermitPortForwarding,
    SshCertExtensionPermitPTY,
    SshCertExtensionPermitUserRC,
    SshCertExtensionSourceAddress,
    SshCertExtensionUnparsed,
    SshCertConstraintVector,
    SshCertCriticalOptionVector,
    SshCertSignature,
    SshCertValidPrincipals,
    SshHostPublicKeyVariant,
    SshHostCertificateV00DSS,
    SshHostCertificateV00RSA,
    SshHostCertificateV01DSS,
    SshHostCertificateV01ECDSA,
    SshHostCertificateV01EDDSA,
    SshHostCertificateV01RSA,
    SshHostKeyDSS,
    SshHostKeyECDSA,
    SshHostKeyEDDSA,
    SshHostKeyRSA,
    SshString,
    SshX509Certificate,
    SshX509CertificateChain,
)


class TestPublicKeyBase(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            SshHostKeyRSA.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 4)

        with self.assertRaises(InvalidValue) as context_manager:
            SshHostKeyRSA.parse_exact_size(b'\x00\x00\x00\x16' + b'non-existing-type-name')
        self.assertEqual(context_manager.exception.value, 'non-existing-type-name')


class TestString(unittest.TestCase):
    def setUp(self):
        self.string_bytes = bytes(
            b'\x00\x00\x00\x06' +
            b'string' +
            b''
        )
        self.string = SshString('string')

    def test_parse(self):
        string = SshString.parse_exact_size(self.string_bytes)
        self.assertEqual(string.value, 'string')

    def test_compose(self):
        self.assertEqual(self.string.compose(), self.string_bytes)


class TestHostKeyDSS(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +               # host_key_algorithm_length
            b'ssh-dss' +                        # host_key_algorithm
            b'\x00\x00\x00\x04' +               # p_length
            b'\x01\x01\x02\x03' +               # p
            b'\x00\x00\x00\x04' +               # q_length
            b'\x04\x05\x06\x07' +               # q
            b'\x00\x00\x00\x04' +               # g_length
            b'\x08\x09\x0a\x0b' +               # g
            b'\x00\x00\x00\x04' +               # y_length
            b'\x0c\x0d\x0e\x0f' +               # y
            b''
        )
        self.host_key = SshHostKeyDSS(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS,
            public_key=PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                order=0x04050607,
                generator=0x08090a0b,
                public_key_value=0x0c0d0e0f,
            )),
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.public_key.params.prime, 0x01010203)
        self.assertEqual(host_key.public_key.params.order, 0x04050607)
        self.assertEqual(host_key.public_key.params.generator, 0x08090a0b)
        self.assertEqual(host_key.public_key.params.public_key_value, 0x0c0d0e0f)
        self.assertEqual(host_key.public_key.key_size, 32)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', 'host key'),
            ('algorithm', Authentication.DSS),
            ('size', PublicKeySize(Authentication.DSS, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:wdClb94C9Lyi38P1o/SEG38glOh3ea5CJl84bZVx2yM='),
                (Hash.SHA1, 'SHA1:fOmDMlRkSkplVc2vGTmkRY65j/c='),
                (Hash.MD5, 'MD5:f2:4f:70:62:fc:36:fa:20:25:62:5d:95:1c:6c:5e:63'),
            ])),
            ('known_hosts', 'AAAAB3NzaC1kc3MAAAAEAQECAwAAAAQEBQYHAAAABAgJCgsAAAAEDA0ODw=='),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_DSS),
            ('public_key', PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                generator=0x08090a0b,
                order=0x04050607,
                public_key_value=0x0c0d0e0f,
            ))),
        ]))


class TestHostKeyRSA(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +               # host_key_algorithm_length
            b'ssh-rsa' +                        # host_key_algorithm
            b'\x00\x00\x00\x04' +               # e_length
            b'\x01\x01\x02\x03' +               # e
            b'\x00\x00\x00\x04' +               # n_length
            b'\x04\x05\x06\x07' +               # n
            b''
        )
        self.host_key = SshHostKeyRSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
            public_key=PublicKey.from_params(PublicKeyParamsRsa(
                modulus=0x04050607,
                public_exponent=0x01010203,
            )),
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        public_key_params = host_key.public_key.params
        self.assertEqual(public_key_params.public_exponent, 0x01010203)
        self.assertEqual(public_key_params.modulus, 0x04050607)
        self.assertEqual(host_key.public_key.key_size, 32)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', 'host key'),
            ('algorithm', Authentication.RSA),
            ('size', PublicKeySize(Authentication.RSA, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:ZuSq5GtQTjPj8LAwY4UE4gGILhIAh5kDaDkkEYLaRU0='),
                (Hash.SHA1, 'SHA1:KAG3KmsLUs4OClEUj62npdXcJTg='),
                (Hash.MD5, 'MD5:0b:40:11:ce:71:86:01:02:2c:7c:9e:13:d9:37:3b:aa'),
            ])),
            ('known_hosts', 'AAAAB3NzaC1yc2EAAAAEAQECAwAAAAQEBQYH'),
        ]))


class TestHostKeyECDSA(TestPublicKeyBase):
    def setUp(self):
        self.point_x_bytes = b'\x80' + (256 // 8 - 1) * b'\x00'
        self.point_y_bytes = b'\x40' + (256 // 8 - 1) * b'\x00'
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x13' +                  # host_key_algorithm_length
            b'ecdsa-sha2-nistp256' +               # host_key_algorithm
            b'\x00\x00\x00\x08' +                  # curve_name_length
            b'nistp256' +                          # curve_name
            b'\x00\x00\x00\x41' +                  # curve_data_length
            b'\04' +                               # curve_data
            self.point_x_bytes +
            self.point_y_bytes +
            b''
        )
        self.host_key = SshHostKeyECDSA(
            host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
            public_key=PublicKey.from_params(PublicKeyParamsEcdsa(
                named_group=NamedGroup.PRIME256V1,
                point_x=2 ** 255,
                point_y=2 ** 254,
            )),
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.public_key.params.named_group, NamedGroup.PRIME256V1)
        self.assertEqual(host_key.public_key.params.point_x, 2 ** 255)
        self.assertEqual(host_key.public_key.params.point_y, 2 ** 254)
        self.assertEqual(host_key.public_key.key_size, 256)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', 'host key'),
            ('algorithm', Authentication.ECDSA),
            ('size', PublicKeySize(Authentication.ECDSA, 256)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:+baTTAvJKIn0rfi1HVlDxDb/lIzi41H9UoCkFPyyO4I='),
                (Hash.SHA1, 'SHA1:WiBKhHvCyV8LpdXgJWrJr9WAhqw='),
                (Hash.MD5, 'MD5:86:c6:d5:ca:3e:5e:82:95:31:80:8a:30:b3:a3:6e:80'),
            ])),
            ('known_hosts', (
                'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIAAAAAAAAAA'
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                'AAAAAAAAAAA='
            )),
        ]))


class TestHostKeyEDDSA(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x0b' +               # host_key_algorithm_length
            b'ssh-ed25519' +                    # host_key_algorithm
            b'\x00\x00\x00\x20' +               # key_data_length
            b'\x00\x01\x02\x03' * 8 +           # key_data
            b''
        )
        self.host_key = SshHostKeyEDDSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
            public_key=PublicKey.from_params(PublicKeyParamsEddsa(
                curve_type=NamedGroup.CURVE25519,
                key_data=b'\x00\x01\x02\x03' * 8,
            )),
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.public_key.params.key_data, b'\x00\x01\x02\x03' * 8)
        self.assertEqual(host_key.public_key.key_size, 256)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', 'host key'),
            ('algorithm', Authentication.EDDSA),
            ('size', PublicKeySize(Authentication.EDDSA, 256)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:tE7ReEqO7s6dpo8PFRQXhAe4Vdy9HkT0UawUx+NfClk='),
                (Hash.SHA1, 'SHA1:0ql0OFSSY06SHsZhtEAJ1Wx2AUo='),
                (Hash.MD5, 'MD5:5c:83:5d:46:c1:7e:b0:47:70:6c:2c:30:a1:28:87:c0'),
            ])),
            ('known_hosts', 'AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMAAQIDAAECAwABAgMAAQIDAAECAwABAgMAAQID'),
        ]))


class TestCertType(unittest.TestCase):
    def test_as_markdown(self):
        self.assertEqual(SshCertType.SSH_CERT_TYPE_USER.value.as_markdown(), 'User')
        self.assertEqual(SshCertType.SSH_CERT_TYPE_HOST.value.as_markdown(), 'Host')


class TestCertExtensionUnparsed(unittest.TestCase):
    def setUp(self):
        self.extension_dict = collections.OrderedDict([
            ('extension_name_length', b'\x00\x00\x00\x10'),
            ('extension_name', b'extension name 1'),
            ('extension_data_length', b'\x00\x00\x00\x10'),
            ('extension_data', b'extension data 1'),
        ])
        self.extension_bytes = b''.join(self.extension_dict.values())

        self.extension = SshCertExtensionUnparsed(
            'extension name 1',
            b'extension data 1',
        )

    def test_parse(self):
        extension = SshCertExtensionUnparsed.parse_exact_size(self.extension_bytes)
        self.assertEqual(extension.extension_name, self.extension.extension_name)
        self.assertEqual(extension.extension_data, self.extension.extension_data)

    def test_compose(self):
        self.assertEqual(self.extension.compose(), self.extension_bytes)


class TestHostCertExtensionsUnparsed(unittest.TestCase):
    def setUp(self):
        self.extensions_bytes = (
            b'\x00\x00\x00\x50' +
            b'\x00\x00\x00\x10' +
            b'extension name 1' +
            b'\x00\x00\x00\x10' +
            b'extension data 1' +
            b'\x00\x00\x00\x10' +
            b'extension name 2' +
            b'\x00\x00\x00\x10' +
            b'extension data 2' +
            b''
        )
        self.extensions = SshCertExtensionVector([
            SshCertExtensionUnparsed('extension name 1', b'extension data 1'),
            SshCertExtensionUnparsed('extension name 2', b'extension data 2'),
        ])

    def test_parse(self):
        self.assertEqual(
            SshCertExtensionVector.parse_exact_size(self.extensions_bytes),
            self.extensions
        )

    def test_compose(self):
        self.assertEqual(self.extensions.compose(), self.extensions_bytes)


class TestHostCertExtensionsNoData(unittest.TestCase):
    def setUp(self):
        self.extensions_bytes = (
            b'\x00\x00\x00\x9e' +
            b'\x00\x00\x00\x14' +
            b'no-presence-required' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x15' +
            b'permit-X11-forwarding' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x17' +
            b'permit-agent-forwarding' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x16' +
            b'permit-port-forwarding' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x0a' +
            b'permit-pty' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x0e' +
            b'permit-user-rc' +
            b'\x00\x00\x00\x00' +
            b''
        )
        self.extensions = SshCertExtensionVector([
            SshCertExtensionNoPrecenseRequired(),
            SshCertExtensionPermitX11Forwarding(),
            SshCertExtensionPermitAgentForwarding(),
            SshCertExtensionPermitPortForwarding(),
            SshCertExtensionPermitPTY(),
            SshCertExtensionPermitUserRC(),
        ])

    def test_parse(self):
        self.assertEqual(
            SshCertExtensionVector.parse_exact_size(self.extensions_bytes),
            self.extensions
        )

    def test_compose(self):
        self.assertEqual(self.extensions.compose(), self.extensions_bytes)


class TestHostCertExtensionsWithData(unittest.TestCase):
    def setUp(self):
        self.extensions_bytes = (
            b'\x00\x00\x00\x4b' +
            b'\x00\x00\x00\x0d' +
            b'force-command'
            b'\x00\x00\x00\x07' +
            b'command'
            b'\x00\x00\x00\x0e' +
            b'source-address' +
            b'\x00\x00\x00\x19' +
            b'192.168.0.0/16,10.0.0.0/8' +
            b''
        )
        self.extensions = SshCertCriticalOptionVector([
            SshCertExtensionForceCommand('command'),
            SshCertExtensionSourceAddress([
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('10.0.0.0/8'),
            ]),
        ])

    def test_parse(self):
        self.assertEqual(
            SshCertCriticalOptionVector.parse_exact_size(self.extensions_bytes),
            self.extensions
        )

    def test_compose(self):
        self.assertEqual(self.extensions.compose(), self.extensions_bytes)


class TestHostCertificateDSSBase(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +  # certificate_type
            b'ssh-dss' +
            b'\x00\x00\x00\x04' +  # p_length
            b'\x01\x01\x02\x03' +  # p
            b'\x00\x00\x00\x04' +  # q_length
            b'\x04\x05\x06\x07' +  # q
            b'\x00\x00\x00\x04' +  # g_length
            b'\x08\x09\x0a\x0b' +  # g
            b'\x00\x00\x00\x04' +  # y_length
            b'\x0c\x0d\x0e\x0f' +  # y
            b'\x00\x00\x00\x13' +
            b'\x00\x00\x00\x07' +  # signature_type
            b'ssh-dss' +
            b'\x00\x00\x00\x04' +  # signature_data
            b'\x00\x01\x02\x03' +
            b''
        )


class TestHostCertificateV00DSS(TestHostCertificateDSSBase):
    def setUp(self):
        super().setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x1c' +
            b'ssh-dss-cert-v00@openssh.com' +
            b'\x00\x00\x00\x04' +  # p_length
            b'\x01\x01\x02\x03' +  # p
            b'\x00\x00\x00\x04' +  # q_length
            b'\x04\x05\x06\x07' +  # q
            b'\x00\x00\x00\x04' +  # g_length
            b'\x08\x09\x0a\x0b' +  # g
            b'\x00\x00\x00\x04' +  # y_length
            b'\x0c\x0d\x0e\x0f' +  # y
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # constraints
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x00' +  # reserved
            b'\x00\x00\x00\x2b' +  # signature_key
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV00DSS(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS_CERT_V00_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                generator=0x08090a0b,
                order=0x04050607,
                public_key_value=0x0c0d0e0f,
            )),
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            constraints=SshCertConstraintVector([]),
            reserved=b'',
            signature_key=SshHostKeyDSS(
                SshHostKeyAlgorithm.SSH_DSS,
                PublicKey.from_params(PublicKeyParamsDsa(
                    prime=0x01010203,
                    generator=0x08090a0b,
                    order=0x04050607,
                    public_key_value=0x0c0d0e0f,
                ))
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.SSH_DSS,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(
            host_cert.public_key.params.prime, self.host_cert.public_key.params.prime
        )
        self.assertEqual(
            host_cert.public_key.params.order, self.host_cert.public_key.params.order
        )
        self.assertEqual(
            host_cert.public_key.params.generator, self.host_cert.public_key.params.generator
        )
        self.assertEqual(
            host_cert.public_key.params.public_key_value, self.host_cert.public_key.params.public_key_value
        )
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.constraints, self.host_cert.constraints)
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.DSS),
            ('size', PublicKeySize(Authentication.DSS, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:JLbl6U9Dd3zrR/pS86OLLJUsL6NU7NOnSd554vL1md0='),
                (Hash.SHA1, 'SHA1:eGd4yAwFTXy+Wdi5xsuEJUNsj0M='),
                (Hash.MD5, 'MD5:01:63:07:cb:45:12:bf:96:4c:fd:62:cd:40:6d:e0:99')
            ])),
            ('known_hosts', (
                'AAAAHHNzaC1kc3MtY2VydC12MDBAb3BlbnNzaC5jb20AAAAEAQECAwAAAAQEBQYH'
                'AAAABAgJCgsAAAAEDA0ODwAAAAIAAAAIAAECAwQFBgcAAAAAAAAAAAAAAAD/////'
                '/////wAAAAAAAAAEAAECAwAAAAAAAAArAAAAB3NzaC1kc3MAAAAEAQECAwAAAAQE'
                'BQYHAAAABAgJCgsAAAAEDA0ODwAAABMAAAAHc3NoLWRzcwAAAAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_DSS_CERT_V00_OPENSSH_COM),
            ('public_key', PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                generator=0x08090a0b,
                order=0x04050607,
                public_key_value=0x0c0d0e0f,
            ))),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('constraints', SshCertConstraintVector([])),
            ('nonce', b'\x00\x01\x02\x03'),
            ('reserved', b''),
            ('signature_key', SshHostKeyDSS(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS,
                public_key=PublicKey.from_params(PublicKeyParamsDsa(
                    prime=0x01010203,
                    generator=0x08090a0b,
                    order=0x04050607,
                    public_key_value=0x0c0d0e0f,
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_DSS,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateV01DSS(TestHostCertificateDSSBase):
    def setUp(self):
        super().setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x1c' +
            b'ssh-dss-cert-v01@openssh.com' +
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x04' +  # p_length
            b'\x01\x01\x02\x03' +  # p
            b'\x00\x00\x00\x04' +  # q_length
            b'\x04\x05\x06\x07' +  # q
            b'\x00\x00\x00\x04' +  # g_length
            b'\x08\x09\x0a\x0b' +  # g
            b'\x00\x00\x00\x04' +  # y_length
            b'\x0c\x0d\x0e\x0f' +  # y
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # serial
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # critical_options
            b'\x00\x00\x00\x00' +  # extensions
            b'\x00\x00\x00\x00' +  # reserved
            b'\x00\x00\x00\x2b' +  # signature_key
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV01DSS(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS_CERT_V01_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                generator=0x08090a0b,
                order=0x04050607,
                public_key_value=0x0c0d0e0f,
            )),
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyDSS(
                SshHostKeyAlgorithm.SSH_DSS,
                PublicKey.from_params(PublicKeyParamsDsa(
                    prime=0x01010203,
                    generator=0x08090a0b,
                    order=0x04050607,
                    public_key_value=0x0c0d0e0f,
                )),
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.SSH_DSS,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(
            host_cert.public_key.params.prime, self.host_cert.public_key.params.prime
        )
        self.assertEqual(
            host_cert.public_key.params.order, self.host_cert.public_key.params.order
        )
        self.assertEqual(
            host_cert.public_key.params.generator, self.host_cert.public_key.params.generator
        )
        self.assertEqual(
            host_cert.public_key.params.public_key_value, self.host_cert.public_key.params.public_key_value
        )
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.critical_options, self.host_cert.critical_options)
        self.assertEqual(host_cert.extensions, SshCertExtensionVector([]))
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.DSS),
            ('size', PublicKeySize(Authentication.DSS, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:81ny5W3AQivvf/ffzLM0b13/eAG82/GsSFNaBnVOF4A='),
                (Hash.SHA1, 'SHA1:Kx6Nzq+MWzKiT4q0lxdQbZzecSo='),
                (Hash.MD5, 'MD5:94:9b:e9:f1:27:4c:7a:60:ba:5b:da:47:99:46:13:06')
            ])),
            ('known_hosts', (
                'AAAAHHNzaC1kc3MtY2VydC12MDFAb3BlbnNzaC5jb20AAAAEAAECAwAAAAQBAQID'
                'AAAABAQFBgcAAAAECAkKCwAAAAQMDQ4PAQIDBAUGBwgAAAACAAAACAABAgMEBQYH'
                'AAAAAAAAAAAAAAAA//////////8AAAAAAAAAAAAAAAAAAAArAAAAB3NzaC1kc3MA'
                'AAAEAQECAwAAAAQEBQYHAAAABAgJCgsAAAAEDA0ODwAAABMAAAAHc3NoLWRzcwAA'
                'AAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_DSS_CERT_V01_OPENSSH_COM),
            ('public_key', PublicKey.from_params(PublicKeyParamsDsa(
                prime=0x01010203,
                generator=0x08090a0b,
                order=0x04050607,
                public_key_value=0x0c0d0e0f,
            ))),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyDSS(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS,
                public_key=PublicKey.from_params(PublicKeyParamsDsa(
                    prime=0x01010203,
                    generator=0x08090a0b,
                    order=0x04050607,
                    public_key_value=0x0c0d0e0f,
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_DSS,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateRSABase(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +  # certificate_type
            b'ssh-rsa' +
            b'\x00\x00\x00\x03' +  # e
            b'\x01\x00\x01' +
            b'\x00\x00\x00\x04' +  # n
            b'\x01\x01\x02\x03' +
            b'\x00\x00\x00\x13' +
            b'\x00\x00\x00\x07' +  # signature_type
            b'ssh-rsa' +
            b'\x00\x00\x00\x04' +  # signature_data
            b'\x00\x01\x02\x03' +
            b''
        )


class TestHostCertificateV00RSA(TestHostCertificateRSABase):
    def setUp(self):
        super().setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x1c' +
            b'ssh-rsa-cert-v00@openssh.com' +
            b'\x00\x00\x00\x01' +  # e
            b'\x03' +
            b'\x00\x00\x00\x04' +  # n
            b'\x01\x01\x02\x03' +
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # constraints
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x00' +  # reserved
            b'\x00\x00\x00\x1a' +  # signature_key
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV00RSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA_CERT_V00_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsRsa(
                public_exponent=0x03,
                modulus=0x01010203,
            )),
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            constraints=SshCertConstraintVector([]),
            reserved=b'',
            signature_key=SshHostKeyRSA(
                SshHostKeyAlgorithm.SSH_RSA,
                PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=0x010001,
                    modulus=0x01010203,
                )),
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.SSH_RSA,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(host_cert.public_key.params.public_exponent, self.host_cert.public_key.params.public_exponent)
        self.assertEqual(host_cert.public_key.params.modulus, self.host_cert.public_key.params.modulus)
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.constraints, self.host_cert.constraints)
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.RSA),
            ('size', PublicKeySize(Authentication.RSA, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:YJVpL0zTCstfPryV5C1tD3boAzBrzRlAMjrAosxw4pA='),
                (Hash.SHA1, 'SHA1:zNRNUIcyRZvu8MuhAmtALdUNCMM='),
                (Hash.MD5, 'MD5:9c:ce:d6:f1:7f:96:d1:5f:9d:14:a3:32:74:a1:18:88')
            ])),
            ('known_hosts', (
                'AAAAHHNzaC1yc2EtY2VydC12MDBAb3BlbnNzaC5jb20AAAABAwAAAAQBAQIDAAAA'
                'AgAAAAgAAQIDBAUGBwAAAAAAAAAAAAAAAP//////////AAAAAAAAAAQAAQIDAAAA'
                'AAAAABoAAAAHc3NoLXJzYQAAAAMBAAEAAAAEAQECAwAAABMAAAAHc3NoLXJzYQAA'
                'AAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_RSA_CERT_V00_OPENSSH_COM),
            ('public_key', PublicKey.from_params(PublicKeyParamsRsa(
                public_exponent=0x03,
                modulus=0x01010203,
            ))),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('constraints', SshCertConstraintVector([])),
            ('nonce', b'\x00\x01\x02\x03'),
            ('reserved', b''),
            ('signature_key', SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                public_key=PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=0x010001,
                    modulus=0x01010203,
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_RSA,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateV01RSA(TestHostCertificateRSABase):
    def setUp(self):
        super().setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x1c' +
            b'ssh-rsa-cert-v01@openssh.com' +
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x01' +  # e
            b'\x03' +
            b'\x00\x00\x00\x04' +  # n
            b'\x01\x01\x02\x03' +
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # serial
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # critical_options
            b'\x00\x00\x00\x00' +  # extensions
            b'\x00\x00\x00\x00' +  # reserved
            b'\x00\x00\x00\x1a' +  # signature_key
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV01RSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsRsa(
                public_exponent=0x03,
                modulus=0x01010203,
            )),
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyRSA(
                SshHostKeyAlgorithm.SSH_RSA,
                PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=0x010001,
                    modulus=0x01010203,
                ))
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.SSH_RSA,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(host_cert.public_key.params.public_exponent, self.host_cert.public_key.params.public_exponent)
        self.assertEqual(host_cert.public_key.params.modulus, self.host_cert.public_key.params.modulus)
        self.assertEqual(host_cert.serial, self.host_cert.serial)
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.critical_options, self.host_cert.critical_options)
        self.assertEqual(host_cert.extensions, SshCertExtensionVector([]))
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.RSA),
            ('size', PublicKeySize(Authentication.RSA, 32)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:vqtvWzklbsElMSGXE0G7Gk7WDHuXzd83KOC0y0Rv9TY='),
                (Hash.SHA1, 'SHA1:9Iem7KW/rAvahTzVMTmDFg93MBk='),
                (Hash.MD5, 'MD5:54:14:e3:b7:d8:7e:fa:d0:3c:52:4b:6a:8f:c4:72:6d')
            ])),
            ('known_hosts', (
                'AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAEAAECAwAAAAEDAAAA'
                'BAEBAgMBAgMEBQYHCAAAAAIAAAAIAAECAwQFBgcAAAAAAAAAAAAAAAD/////////'
                '/wAAAAAAAAAAAAAAAAAAABoAAAAHc3NoLXJzYQAAAAMBAAEAAAAEAQECAwAAABMA'
                'AAAHc3NoLXJzYQAAAAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM),
            ('public_key', PublicKey.from_params(PublicKeyParamsRsa(
                public_exponent=0x03,
                modulus=0x01010203,
            ))),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                public_key=PublicKey.from_params(PublicKeyParamsRsa(
                    public_exponent=0x010001,
                    modulus=0x01010203,
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_RSA,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateECDSABase(TestPublicKeyBase):
    def setUp(self):
        self.point_x_bytes = b'\x80' + (256 // 8 - 1) * b'\x00'
        self.point_y_bytes = b'\x40' + (256 // 8 - 1) * b'\x00'
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x13' +  # certificate_type
            b'ecdsa-sha2-nistp256' +
            b'\x00\x00\x00\x08' +     # curve_name_length
            b'nistp256' +             # curve_name
            b'\x00\x00\x00\x41' +     # curve_data_length
            b'\x04' +                 # curve_data
            self.point_x_bytes +
            self.point_y_bytes +
            b'\x00\x00\x00\x1f' +
            b'\x00\x00\x00\x13' +  # signature_type
            b'ecdsa-sha2-nistp256' +
            b'\x00\x00\x00\x04' +  # signature_data
            b'\x00\x01\x02\x03' +
            b''
        )


class TestHostCertificateV01ECDSA(TestHostCertificateECDSABase):
    def setUp(self):
        super().setUp()
        self.point_x_bytes = b'\x80' + (256 // 8 - 1) * b'\x00'
        self.point_y_bytes = b'\x40' + (256 // 8 - 1) * b'\x00'
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x28' +
            b'ecdsa-sha2-nistp256-cert-v01@openssh.com' +
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x08' +     # curve_name_length
            b'nistp256' +             # curve_name
            b'\x00\x00\x00\x41' +     # curve_data_length
            b'\x04' +                 # curve_data
            self.point_x_bytes +
            self.point_y_bytes +
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # serial
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # critical_options
            b'\x00\x00\x00\x00' +  # extensions
            b'\x00\x00\x00\x00' +  # reserved
            b'\x00\x00\x00\x68' +  # signature_key
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV01ECDSA(
            host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsEcdsa(
                named_group=NamedGroup.PRIME256V1,
                point_x=2 ** 255,
                point_y=2 ** 254,
            )),
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyECDSA(
                host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                public_key=PublicKey.from_params(PublicKeyParamsEcdsa(
                    named_group=NamedGroup.PRIME256V1,
                    point_x=2 ** 255,
                    point_y=2 ** 254,
                )),
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(host_cert.public_key.params.named_group, NamedGroup.PRIME256V1)
        self.assertEqual(host_cert.public_key.params.point_x, 2 ** 255)
        self.assertEqual(host_cert.public_key.params.point_y, 2 ** 254)
        self.assertEqual(host_cert.serial, self.host_cert.serial)
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.critical_options, self.host_cert.critical_options)
        self.assertEqual(host_cert.extensions, SshCertExtensionVector([]))
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.ECDSA),
            ('size', PublicKeySize(Authentication.ECDSA, 256)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:aRBBmsAqpnH3wrOh35fa//LB/JGcuTUAPuRPEj9RWRQ='),
                (Hash.SHA1, 'SHA1:9E5qN+JPZBX4ZBfKEou/WNWtWR8='),
                (Hash.MD5, 'MD5:e9:dd:20:42:a4:36:6b:90:60:29:f8:69:5f:be:e7:13')
            ])),
            ('known_hosts', (
                'AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAE'
                'AAECAwAAAAhuaXN0cDI1NgAAAEEEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                'AAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcIAAAA'
                'AgAAAAgAAQIDBAUGBwAAAAAAAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAA'
                'aAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSAAAAAAAAA'
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                'AAAAAAAAAAAAAAAAHwAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAABAABAgM='
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM),

            ('public_key', PublicKey.from_params(PublicKeyParamsEcdsa(
                named_group=NamedGroup.PRIME256V1,
                point_x=2 ** 255,
                point_y=2 ** 254,
            ))),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyECDSA(
                host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                public_key=PublicKey.from_params(PublicKeyParamsEcdsa(
                    named_group=NamedGroup.PRIME256V1,
                    point_x=2 ** 255,
                    point_y=2 ** 254,
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateEDDSABase(TestPublicKeyBase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x17' +  # certificate_type
            b'\x00\x00\x00\x0b' +  # host_key_algorithm
            b'ssh-ed25519' +
            b'\x00\x00\x00\x04' +     # key_data_length
            b'\x00\x01\x02\x03' +     # key_data
            b'\x00\x00\x00\x17' +
            b'\x00\x00\x00\x0b' +  # signature_type
            b'ssh-ed25519' +
            b'\x00\x00\x00\x04' +  # signature_data
            b'\x00\x01\x02\x03' +
            b''
        )


class TestHostCertificateV01EDDSA(TestHostCertificateEDDSABase):
    def setUp(self):
        super().setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x20' +
            b'ssh-ed25519-cert-v01@openssh.com' +
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x04' +     # key_data_length
            b'\x00\x01\x02\x03' +     # key_data
            b'\x01\x02\x03\x04\x05\x06\x07\x08' +  # serial
            b'\x00\x00\x00\x02' +  # certificate_type (SshCertType.SSH_CERT_TYPE_HOST)
            b'\x00\x00\x00\x08' +  # key_id
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x00\x00\x00\x00' +  # valid_principals
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # valid_after
            b'\xff\xff\xff\xff\xff\xff\xff\xff' +  # valid_before
            b'\x00\x00\x00\x00' +  # critical_options
            b'\x00\x00\x00\x00' +  # extensions
            b'\x00\x00\x00\x00' +  # reserved
            self.host_key_bytes +
            b''
        )
        self.host_cert = SshHostCertificateV01EDDSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            public_key=PublicKey.from_params(PublicKeyParamsEddsa(
                curve_type=NamedGroup.CURVE25519,
                key_data=b'\x00\x01\x02\x03',
            )),
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyEDDSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
                public_key=PublicKey.from_params(PublicKeyParamsEddsa(
                    curve_type=NamedGroup.CURVE25519,
                    key_data=b'\x00\x01\x02\x03',
                )),
            ),
            signature=SshCertSignature(
                SshHostKeyAlgorithm.SSH_ED25519,
                b'\x00\x01\x02\x03',
            )
        )

    def test_parse(self):
        host_cert = SshHostPublicKeyVariant.parse_exact_size(self.host_cert_bytes)

        self.assertEqual(host_cert.host_key_algorithm, self.host_cert.host_key_algorithm)
        self.assertEqual(host_cert.nonce, self.host_cert.nonce)
        self.assertEqual(host_cert.public_key.params.key_data, b'\x00\x01\x02\x03')
        self.assertEqual(host_cert.serial, self.host_cert.serial)
        self.assertEqual(host_cert.certificate_type, self.host_cert.certificate_type)
        self.assertEqual(host_cert.key_id, self.host_cert.key_id)
        self.assertEqual(host_cert.valid_principals, self.host_cert.valid_principals)
        self.assertEqual(host_cert.valid_after, self.host_cert.valid_after)
        self.assertEqual(host_cert.valid_before, self.host_cert.valid_before)
        self.assertEqual(host_cert.critical_options, self.host_cert.critical_options)
        self.assertEqual(host_cert.extensions, SshCertExtensionVector([]))
        self.assertEqual(host_cert.reserved, self.host_cert.reserved)
        self.assertEqual(host_cert.signature_key, self.host_cert.signature_key)
        self.assertEqual(host_cert.signature, self.host_cert.signature)

    def test_compose(self):
        self.assertEqual(self.host_cert.compose(), self.host_cert_bytes)
        self.assertEqual(self.host_cert.key_bytes, self.host_cert_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_cert._asdict(), OrderedDict([
            ('key_type', 'host certificate'),
            ('algorithm', Authentication.EDDSA),
            ('size', PublicKeySize(Authentication.EDDSA, 256)),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:IDjjwI5W2lkjfR/gnU0pvSw6E340LushvP/N9A1HrWg='),
                (Hash.SHA1, 'SHA1:EXpev7tY2XCP2R0G6eqcqNgBpOc='),
                (Hash.MD5, 'MD5:74:06:06:3f:aa:1f:a8:34:1f:1e:6c:16:26:4c:fd:6e')
            ])),
            ('known_hosts', (
                'AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAABAABAgMAAAAE'
                'AAECAwECAwQFBgcIAAAAAgAAAAgAAQIDBAUGBwAAAAAAAAAAAAAAAP//////////'
                'AAAAAAAAAAAAAAAAAAAAFwAAAAtzc2gtZWQyNTUxOQAAAAQAAQIDAAAAFwAAAAtz'
                'c2gtZWQyNTUxOQAAAAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM),
            ('public_key', PublicKey.from_params(PublicKeyParamsEddsa(
                curve_type=NamedGroup.CURVE25519,
                key_data=b'\x00\x01\x02\x03',
            ))),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, datetime.timezone.utc)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyEDDSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
                public_key=PublicKey.from_params(PublicKeyParamsEddsa(
                    curve_type=NamedGroup.CURVE25519,
                    key_data=b'\x00\x01\x02\x03',
                )),
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_ED25519,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestX509CertificateChain(TestClasses.TestKeyBase):
    def setUp(self):
        super().setUp()

        x509_certificate = self._get_public_key_x509('snakeoil_cert.pem')
        self.x509_certificate_bytes = x509_certificate.der

        self.x509v3_ssh_rsa_certificate_bytes = bytes(
            b'\x00\x00\x00\x0e' +  # host_key_algorithm
            b'x509v3-ssh-rsa' +
            b'\x00\x00\x00\x01' +  # certificate_count
            b'\x00\x00\x03\xc4' +  # certificate_length
            self.x509_certificate_bytes +
            b'\x00\x00\x00\x01' +  # ocsp_response_count
            b'\x00\x00\x00\x04' +  # ocsp_response_length
            b'\x00\x01\x02\x03' +
            b''
        )

        self.x509v3_ssh_rsa_certificate = SshX509CertificateChain(
            SshHostKeyAlgorithm.X509V3_SSH_RSA, x509_certificate, [], [b'\x00\x01\x02\x03']
        )

    def test_key_bytes(self):
        self.assertEqual(
            self.x509v3_ssh_rsa_certificate.key_bytes,
            self.x509v3_ssh_rsa_certificate.public_key.key_bytes
        )

    def test_asdict(self):
        dict_result = self.x509v3_ssh_rsa_certificate._asdict()
        self.assertEqual(list(dict_result.keys())[-2:], ['key_type', 'certificate_chain'])
        self.assertEqual(dict_result.pop('key_type'), 'X.509 certificate chain')
        self.assertEqual(dict_result.pop('certificate_chain'), [self.x509v3_ssh_rsa_certificate.public_key])

    def test_parse(self):
        x509_certificate = SshX509CertificateChain.parse_exact_size(self.x509v3_ssh_rsa_certificate_bytes)
        self.assertEqual(x509_certificate.host_key_algorithm, SshHostKeyAlgorithm.X509V3_SSH_RSA)
        self.assertEqual(x509_certificate.public_key, self.x509v3_ssh_rsa_certificate.public_key)
        self.assertEqual(x509_certificate.issuer_certificates, [])
        self.assertEqual(x509_certificate.ocsp_responses, [b'\x00\x01\x02\x03'])

    def test_compose(self):
        self.assertEqual(self.x509v3_ssh_rsa_certificate.compose(), self.x509v3_ssh_rsa_certificate_bytes)


class TestX509Certificate(TestClasses.TestKeyBase):
    def setUp(self):
        super().setUp()

        self.x509v3_sign_rsa_header = bytes(
            b'\x00\x00\x00\x14' +  # host_key_algorithm
            b'x509v3-sign-rsa-sha1' +
            b'\x00\x00\x03\xc4' +  # public_key_length
            b''
        )

        self.x509_certificate = self._get_public_key_x509('snakeoil_cert.pem')
        self.x509_certificate_bytes = self.x509_certificate.der

        self.x509v3_sign_rsa_certificate = SshX509Certificate(
            SshHostKeyAlgorithm.X509V3_SIGN_RSA, self.x509_certificate
        )
        self.x509v3_sign_rsa_sha1_certificate = SshX509Certificate(
            SshHostKeyAlgorithm.X509V3_SIGN_RSA_SHA1, self.x509_certificate
        )

    def test_error_invalid_type(self):
        x509_certificate_bytes = self._get_public_key_x509('ecc256.badssl.com.pem').der
        with self.assertRaises(InvalidType):
            SshX509Certificate.parse_exact_size(x509_certificate_bytes)

    def test_error_invalid_certificate_value(self):
        with self.assertRaises(InvalidValue) as context_manager:
            SshX509Certificate.parse_exact_size(self.x509v3_sign_rsa_header)
        self.assertEqual(context_manager.exception.value, b'')

    def test_parse_with_host_key_type(self):
        x509_certificate = SshX509Certificate.parse_exact_size(
            self.x509v3_sign_rsa_header + self.x509_certificate_bytes
        )
        self.assertEqual(x509_certificate.host_key_algorithm, SshHostKeyAlgorithm.X509V3_SIGN_RSA_SHA1)
        self.assertEqual(x509_certificate.public_key, self.x509v3_sign_rsa_certificate.public_key)

    def test_parse_without_host_key_type(self):
        x509_certificate = SshX509Certificate.parse_exact_size(self.x509_certificate_bytes)
        self.assertEqual(x509_certificate.host_key_algorithm, SshHostKeyAlgorithm.X509V3_SIGN_RSA)
        self.assertEqual(x509_certificate.public_key, self.x509v3_sign_rsa_certificate.public_key)

    def test_key_bytes(self):
        self.assertEqual(self.x509v3_sign_rsa_certificate.key_bytes, self.x509_certificate.public_key.key_bytes)

    def test_compose_with_host_key_type(self):
        self.assertEqual(
            self.x509v3_sign_rsa_sha1_certificate.compose(),
            self.x509v3_sign_rsa_header + self.x509_certificate_bytes
        )

    def test_compose_without_host_key_type(self):
        self.assertEqual(self.x509v3_sign_rsa_certificate.compose(), self.x509_certificate_bytes)
