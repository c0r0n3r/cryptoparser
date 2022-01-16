#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from collections import OrderedDict

from cryptoparser.common.algorithm import Hash, Authentication
from cryptoparser.common.exception import InvalidValue, NotEnoughData

from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithm
from cryptoparser.ssh.key import (
    SshHostPublicKeyVariant,
    SshHostKeyDSS,
    SshHostKeyRSA,
    SshHostKeyECDSA,
    SshHostKeyEDDSA,
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


class TestHostKeyDSS(unittest.TestCase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +               # host_key_algorithm_length
            b'ssh-dss' +                        # host_key_algorithm
            b'\x00\x00\x00\x04' +               # p_length
            b'\x00\x01\x02\x03' +               # p
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
            p=b'\x00\x01\x02\x03',
            q=b'\x04\x05\x06\x07',
            g=b'\x08\x09\x0a\x0b',
            y=b'\x0c\x0d\x0e\x0f',
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.p, b'\x00\x01\x02\x03')
        self.assertEqual(host_key.q, b'\x04\x05\x06\x07')
        self.assertEqual(host_key.g, b'\x08\x09\x0a\x0b')
        self.assertEqual(host_key.y, b'\x0c\x0d\x0e\x0f')
        self.assertEqual(host_key.key_size, 24)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('known_hosts', 'AAAAB3NzaC1kc3MAAAAEAAECAwAAAAQEBQYHAAAABAgJCgsAAAAEDA0ODw=='),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:lEPxr9u8WS8znTORYUn96XCgk3oLL6inrDPtZtjJAIU='),
                (Hash.SHA1, 'SHA1:J4w+3Z3ZXqjGIvAPiBvVVmKooMQ='),
                (Hash.MD5, 'MD5:1d:dc:2f:78:65:e2:b0:eb:33:3c:5c:a1:e6:ab:d9:8b'),
            ])),
            ('key_type', Authentication.DSS),
            ('key_name', SshHostKeyAlgorithm.SSH_DSS),
            ('key_size', 24),
        ]))


class TestHostKeyRSA(unittest.TestCase):
    def setUp(self):
        self.host_key_bytes = bytes(
            b'\x00\x00\x00\x07' +               # host_key_algorithm_length
            b'ssh-rsa' +                        # host_key_algorithm
            b'\x00\x00\x00\x04' +               # exponent_length
            b'\x00\x01\x02\x03' +               # exponent
            b'\x00\x00\x00\x04' +               # modulus_length
            b'\x04\x05\x06\x07' +               # modulus
            b''
        )
        self.host_key = SshHostKeyRSA(
            host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
            exponent=b'\x00\x01\x02\x03',
            modulus=b'\x04\x05\x06\x07',
        )

    def test_parse(self):
        host_key = SshHostPublicKeyVariant.parse_exact_size(self.host_key_bytes)
        self.assertEqual(host_key.exponent, b'\x00\x01\x02\x03')
        self.assertEqual(host_key.modulus, b'\x04\x05\x06\x07')
        self.assertEqual(host_key.key_size, 24)

    def test_compose(self):
        self.assertEqual(self.host_key.compose(), self.host_key_bytes)

    def test_asdict(self):
        self.assertEqual(self.host_key._asdict(), OrderedDict([
            ('known_hosts', 'AAAAB3NzaC1yc2EAAAAEAAECAwAAAAQEBQYH'),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:FnFNj+ZfblG+vS4Nf5hGsYREPdThfPMSfrw1C5NKii0='),
                (Hash.SHA1, 'SHA1:vnrbaS5XtHUQZrTFZ3c7ftyvNa4='),
                (Hash.MD5, 'MD5:30:e8:0a:83:b5:9e:b5:6a:8a:4c:0c:f1:4b:58:10:1b'),
            ])),
            ('key_type', Authentication.RSA),
            ('key_name', SshHostKeyAlgorithm.SSH_RSA),
            ('key_size', 24),
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
            ('known_hosts', 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAAEAAECAw=='),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:W1agtTnzki6Rcqu/dMFfzswy99uD8TsO11b5Fk6RDUo='),
                (Hash.SHA1, 'SHA1:02+/4xDo1z/zl1l1QRTb5uBxnGg='),
                (Hash.MD5, 'MD5:2f:b0:36:9d:54:d5:56:ce:a7:be:84:da:8c:08:f9:dc'),
            ])),
            ('key_type', Authentication.ECDSA),
            ('key_name', SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256),
            ('key_size', 256),
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
            ('known_hosts', 'AAAAC3NzaC1lZDI1NTE5AAAABAABAgM='),
            ('fingerprints', OrderedDict([
                (Hash.SHA2_256, 'SHA256:tisjNupmcCLFV3HIx3sTEZMsjE8wuPrxRta6wD7P2qE='),
                (Hash.SHA1, 'SHA1:LnkkIzv+iqBzToK/hB/Ou2vjbQw='),
                (Hash.MD5, 'MD5:90:d1:22:82:5e:7e:e0:cc:dc:1a:74:aa:14:c8:51:b3'),
            ])),
            ('key_type', Authentication.EDDSA),
            ('key_name', SshHostKeyAlgorithm.SSH_ED25519),
            ('key_size', 32),
        ]))
