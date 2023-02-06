#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)


class TestSshAlgorithm(unittest.TestCase):
    def test_str(self):
        self.assertEqual(str(SshEncryptionAlgorithm.ACSS_OPENSSH_ORG.value), 'acss@openssh.org')
        self.assertEqual(str(SshMacAlgorithm.CRYPTICORE_MAC_SSH_COM.value), 'crypticore-mac@ssh.com')
        self.assertEqual(str(SshKexAlgorithm.DIFFIE_HELLMAN_GROUP1_SHA1.value), 'diffie-hellman-group1-sha1')
        self.assertEqual(str(SshHostKeyAlgorithm.SSH_ED25519.value), 'ssh-ed25519')
        self.assertEqual(str(SshCompressionAlgorithm.ZLIB_OPENSSH_COM.value), 'zlib@openssh.com')


class TestSshAlgorithmMac(unittest.TestCase):
    def test_size(self):
        self.assertEqual(SshMacAlgorithm.HMAC_SHA2_256.value.size, 256)
        self.assertEqual(SshMacAlgorithm.HMAC_SHA2_256_96.value.size, 96)
