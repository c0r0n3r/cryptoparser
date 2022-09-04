#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import collections
import datetime
import ipaddress
import unittest

from collections import OrderedDict

import dateutil.tz

from cryptoparser.common.algorithm import Hash, Authentication

from cryptoparser.common.exception import InvalidValue, NotEnoughData

from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithm
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
)


class TestPublicKeyBase(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            SshHostKeyRSA.parse_exact_size(b'')
        self.assertEqual(context_manager.exception.bytes_needed, 4)

        with self.assertRaises(InvalidValue) as context_manager:
            SshHostKeyRSA.parse_exact_size(b'\x00\x00\x00\x18' + b'non-existing-type-name')
        self.assertEqual(context_manager.exception.value, b'non-existing-type-name')

        with self.assertRaises(NotImplementedError):
            SshHostKeyRSA.get_digest(Hash.MD4, b'')


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


class TestHostKeyDSS(unittest.TestCase):
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
            p=0x01010203,
            q=0x04050607,
            g=0x08090a0b,
            y=0x0c0d0e0f,
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.p, 0x01010203)
        self.assertEqual(host_key.q, 0x04050607)
        self.assertEqual(host_key.g, 0x08090a0b)
        self.assertEqual(host_key.y, 0x0c0d0e0f)
        self.assertEqual(host_key.key_size, 32)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', Authentication.DSS),
            ('key_name', SshHostKeyAlgorithm.SSH_DSS),
            ('key_size', 32),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:wdClb94C9Lyi38P1o/SEG38glOh3ea5CJl84bZVx2yM='),
                (Hash.SHA1, 'SHA1:fOmDMlRkSkplVc2vGTmkRY65j/c='),
                (Hash.MD5, 'MD5:f2:4f:70:62:fc:36:fa:20:25:62:5d:95:1c:6c:5e:63'),
            ])),
            ('known_hosts', 'AAAAB3NzaC1kc3MAAAAEAQECAwAAAAQEBQYHAAAABAgJCgsAAAAEDA0ODw=='),
            ('host_key_algorithm', SshHostKeyAlgorithm.SSH_DSS),
            ('p', 0x01010203),
            ('g', 0x08090a0b),
            ('q', 0x04050607),
            ('y', 0x0c0d0e0f),
        ]))


class TestHostKeyRSA(unittest.TestCase):
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
            e=0x01010203,
            n=0x04050607,
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.e, 0x01010203)
        self.assertEqual(host_key.n, 0x04050607)
        self.assertEqual(host_key.key_size, 32)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', Authentication.RSA),
            ('key_name', SshHostKeyAlgorithm.SSH_RSA),
            ('key_size', 32),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:ZuSq5GtQTjPj8LAwY4UE4gGILhIAh5kDaDkkEYLaRU0='),
                (Hash.SHA1, 'SHA1:KAG3KmsLUs4OClEUj62npdXcJTg='),
                (Hash.MD5, 'MD5:0b:40:11:ce:71:86:01:02:2c:7c:9e:13:d9:37:3b:aa'),
            ])),
            ('known_hosts', 'AAAAB3NzaC1yc2EAAAAEAQECAwAAAAQEBQYH'),
        ]))


class TestHostKeyECDSA(unittest.TestCase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x13' +               # host_key_algorithm_length
            b'ecdsa-sha2-nistp256' +            # host_key_algorithm
            b'\x00\x00\x00\x08' +               # curve_name_length
            b'nistp256' +                       # curve_name
            b'\x00\x00\x00\x04' +               # curve_data_length
            b'\x00\x01\x02\x03' +               # curve_data
            b''
        )
        self.host_key = SshHostKeyECDSA(
            host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
            curve_name='nistp256',
            curve_data=b'\x00\x01\x02\x03',
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.curve_name, 'nistp256')
        self.assertEqual(host_key.curve_data, b'\x00\x01\x02\x03')
        self.assertEqual(host_key.key_size, 256)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', Authentication.ECDSA),
            ('key_name', SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256),
            ('key_size', 256),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:W1agtTnzki6Rcqu/dMFfzswy99uD8TsO11b5Fk6RDUo='),
                (Hash.SHA1, 'SHA1:02+/4xDo1z/zl1l1QRTb5uBxnGg='),
                (Hash.MD5, 'MD5:2f:b0:36:9d:54:d5:56:ce:a7:be:84:da:8c:08:f9:dc'),
            ])),
            ('known_hosts', 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAEAAECAw=='),
        ]))


class TestHostKeyEDDSA(unittest.TestCase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x0b' +               # host_key_algorithm_length
            b'ssh-ed25519' +                    # host_key_algorithm
            b'\x00\x00\x00\x04' +               # key_data_length
            b'\x00\x01\x02\x03' +               # key_data
            b''
        )
        self.host_key = SshHostKeyEDDSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
            key_data=b'\x00\x01\x02\x03',
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.key_data, b'\x00\x01\x02\x03')
        self.assertEqual(host_key.key_size, 32)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('key_type', Authentication.EDDSA),
            ('key_name', SshHostKeyAlgorithm.SSH_ED25519),
            ('key_size', 32),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:tisjNupmcCLFV3HIx3sTEZMsjE8wuPrxRta6wD7P2qE='),
                (Hash.SHA1, 'SHA1:LnkkIzv+iqBzToK/hB/Ou2vjbQw='),
                (Hash.MD5, 'MD5:90:d1:22:82:5e:7e:e0:cc:dc:1a:74:aa:14:c8:51:b3'),
            ])),
            ('known_hosts', 'AAAAC3NzaC1lZDI1NTE5AAAABAABAgM='),
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


class TestHostCertificateDSSBase(unittest.TestCase):
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
        super(TestHostCertificateV00DSS, self).setUp()
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
            p=0x01010203,
            q=0x04050607,
            g=0x08090a0b,
            y=0x0c0d0e0f,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            constraints=SshCertConstraintVector([]),
            reserved=b'',
            signature_key=SshHostKeyDSS(
                SshHostKeyAlgorithm.SSH_DSS,
                p=0x01010203,
                q=0x04050607,
                g=0x08090a0b,
                y=0x0c0d0e0f,
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
        self.assertEqual(host_cert.p, self.host_cert.p)
        self.assertEqual(host_cert.q, self.host_cert.q)
        self.assertEqual(host_cert.g, self.host_cert.g)
        self.assertEqual(host_cert.y, self.host_cert.y)
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
            ('key_type', Authentication.DSS),
            ('key_name', SshHostKeyAlgorithm.SSH_DSS_CERT_V00_OPENSSH_COM),
            ('key_size', 32),
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
            ('p', 0x01010203),
            ('g', 0x08090a0b),
            ('q', 0x04050607),
            ('y', 0x0c0d0e0f),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('constraints', SshCertConstraintVector([])),
            ('nonce', b'\x00\x01\x02\x03'),
            ('reserved', b''),
            ('signature_key', SshHostKeyDSS(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS,
                p=0x01010203,
                g=0x08090a0b,
                q=0x04050607,
                y=0x0c0d0e0f,
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_DSS,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateV01DSS(TestHostCertificateDSSBase):
    def setUp(self):
        super(TestHostCertificateV01DSS, self).setUp()
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
            p=0x01010203,
            q=0x04050607,
            g=0x08090a0b,
            y=0x0c0d0e0f,
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyDSS(
                SshHostKeyAlgorithm.SSH_DSS,
                p=0x01010203,
                q=0x04050607,
                g=0x08090a0b,
                y=0x0c0d0e0f,
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
        self.assertEqual(host_cert.p, self.host_cert.p)
        self.assertEqual(host_cert.q, self.host_cert.q)
        self.assertEqual(host_cert.g, self.host_cert.g)
        self.assertEqual(host_cert.y, self.host_cert.y)
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
            ('key_type', Authentication.DSS),
            ('key_name', SshHostKeyAlgorithm.SSH_DSS_CERT_V01_OPENSSH_COM),
            ('key_size', 32),
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
            ('p', 0x01010203),
            ('g', 0x08090a0b),
            ('q', 0x04050607),
            ('y', 0x0c0d0e0f),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyDSS(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_DSS,
                p=0x01010203,
                q=0x04050607,
                g=0x08090a0b,
                y=0x0c0d0e0f,
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_DSS,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateRSABase(unittest.TestCase):
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
        super(TestHostCertificateV00RSA, self).setUp()
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
            e=0x03,
            n=0x01010203,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            constraints=SshCertConstraintVector([]),
            reserved=b'',
            signature_key=SshHostKeyRSA(
                SshHostKeyAlgorithm.SSH_RSA,
                e=0x010001,
                n=0x01010203,
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
        self.assertEqual(host_cert.e, self.host_cert.e)
        self.assertEqual(host_cert.n, self.host_cert.n)
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
            ('key_type', Authentication.RSA),
            ('key_name', SshHostKeyAlgorithm.SSH_RSA_CERT_V00_OPENSSH_COM),
            ('key_size', 32),
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
            ('e', 0x03),
            ('n', 0x01010203),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('constraints', SshCertConstraintVector([])),
            ('nonce', b'\x00\x01\x02\x03'),
            ('reserved', b''),
            ('signature_key', SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                e=0x010001,
                n=0x01010203,
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_RSA,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateV01RSA(TestHostCertificateRSABase):
    def setUp(self):
        super(TestHostCertificateV01RSA, self).setUp()
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
            e=0x03,
            n=0x01010203,
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyRSA(
                SshHostKeyAlgorithm.SSH_RSA,
                e=0x010001,
                n=0x01010203,
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
        self.assertEqual(host_cert.e, self.host_cert.e)
        self.assertEqual(host_cert.n, self.host_cert.n)
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
            ('key_type', Authentication.RSA),
            ('key_name', SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM),
            ('key_size', 32),
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
            ('e', 0x03),
            ('n', 0x01010203),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                e=0x010001,
                n=0x01010203,
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_RSA,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateECDSABase(unittest.TestCase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x13' +  # certificate_type
            b'ecdsa-sha2-nistp256' +
            b'\x00\x00\x00\x08' +     # curve_name_length
            b'nistp256' +             # curve_name
            b'\x00\x00\x00\x04' +     # curve_data_length
            b'\x00\x01\x02\x03' +     # curve_data
            b'\x00\x00\x00\x1f' +
            b'\x00\x00\x00\x13' +  # signature_type
            b'ecdsa-sha2-nistp256' +
            b'\x00\x00\x00\x04' +  # signature_data
            b'\x00\x01\x02\x03' +
            b''
        )


class TestHostCertificateV01ECDSA(TestHostCertificateECDSABase):
    def setUp(self):
        super(TestHostCertificateV01ECDSA, self).setUp()
        self.host_cert_bytes = bytes(
            b'\x00\x00\x00\x28' +
            b'ecdsa-sha2-nistp256-cert-v01@openssh.com' +
            b'\x00\x00\x00\x04' +  # nonce
            b'\x00\x01\x02\x03' +
            b'\x00\x00\x00\x08' +     # curve_name_length
            b'nistp256' +             # curve_name
            b'\x00\x00\x00\x04' +     # curve_data_length
            b'\x00\x01\x02\x03' +     # curve_data
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
        self.host_cert = SshHostCertificateV01ECDSA(
            host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
            nonce=b'\x00\x01\x02\x03',
            curve_name='nistp256',
            curve_data=b'\x00\x01\x02\x03',
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyECDSA(
                host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                curve_name='nistp256',
                curve_data=b'\x00\x01\x02\x03',
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
        self.assertEqual(host_cert.curve_name, 'nistp256')
        self.assertEqual(host_cert.curve_data, b'\x00\x01\x02\x03')
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
            ('key_type', Authentication.ECDSA),
            ('key_name', SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM),
            ('key_size', 256),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:nkIe7wYOgpTlPC6ZHpHX5z/EGJap9XwDfpYDKAyUGxc='),
                (Hash.SHA1, 'SHA1:lNN9i6zcuV9XaMtsK6aqc03P6KU='),
                (Hash.MD5, 'MD5:3d:bb:bd:3d:ff:8b:09:7e:ae:77:24:d4:0f:3a:44:75')
            ])),
            ('known_hosts', (
                'AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAE'
                'AAECAwAAAAhuaXN0cDI1NgAAAAQAAQIDAQIDBAUGBwgAAAACAAAACAABAgMEBQYH'
                'AAAAAAAAAAAAAAAA//////////8AAAAAAAAAAAAAAAAAAAArAAAAE2VjZHNhLXNo'
                'YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAEAAECAwAAAB8AAAATZWNkc2Etc2hh'
                'Mi1uaXN0cDI1NgAAAAQAAQID'
            )),
            ('host_key_algorithm', SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM),
            ('curve_name', 'nistp256'),
            ('curve_data', b'\x00\x01\x02\x03'),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyECDSA(
                host_key_algorithm=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                curve_name='nistp256',
                curve_data=b'\x00\x01\x02\x03',
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))


class TestHostCertificateEDDSABase(unittest.TestCase):
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
        super(TestHostCertificateV01EDDSA, self).setUp()
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
            key_data=b'\x00\x01\x02\x03',
            serial=0x0102030405060708,
            certificate_type=SshCertType.SSH_CERT_TYPE_HOST,
            key_id='\x00\x01\x02\x03\x04\x05\x06\x07',
            valid_principals=SshCertValidPrincipals([]),
            valid_after=datetime.datetime.fromtimestamp(0, dateutil.tz.UTC),
            valid_before=None,
            critical_options=SshCertCriticalOptionVector([]),
            extensions=SshCertExtensionVector([]),
            reserved=b'',
            signature_key=SshHostKeyEDDSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
                key_data=b'\x00\x01\x02\x03',
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
        self.assertEqual(host_cert.key_data, b'\x00\x01\x02\x03')
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
            ('key_type', Authentication.EDDSA),
            ('key_name', SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM),
            ('key_size', 32),
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
            ('key_data', b'\x00\x01\x02\x03'),
            ('nonce', b'\x00\x01\x02\x03'),
            ('serial', 0x0102030405060708),
            ('certificate_type', SshCertType.SSH_CERT_TYPE_HOST),
            ('key_id', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('valid_principals', SshCertValidPrincipals([])),
            ('valid_after', datetime.datetime.fromtimestamp(0, dateutil.tz.UTC)),
            ('valid_before', None),
            ('critical_options', SshCertCriticalOptionVector([])),
            ('extensions', SshCertExtensionVector([])),
            ('reserved', b''),
            ('signature_key', SshHostKeyEDDSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_ED25519,
                key_data=b'\x00\x01\x02\x03',
            )),
            ('signature', SshCertSignature(
                signature_type=SshHostKeyAlgorithm.SSH_ED25519,
                signature_data=b'\x00\x01\x02\x03'
            ))
        ]))
