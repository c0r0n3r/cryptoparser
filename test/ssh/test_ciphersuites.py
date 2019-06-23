#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.ssh.ciphersuite import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)


class TestSshAlgorithm(unittest.TestCase):
    def test_markdown(self):
        self.assertEqual(SshEncryptionAlgorithm.ACSS_OPENSSH_ORG.value.as_markdown(), 'acss@openssh.org')
        self.assertEqual(SshMacAlgorithm.CRYPTICORE_MAC_SSH_COM.value.as_markdown(), 'crypticore-mac@ssh.com')
        self.assertEqual(SshKexAlgorithm.DIFFIE_HELLMAN_GROUP1_SHA1.value.as_markdown(), 'diffie-hellman-group1-sha1')
        self.assertEqual(SshHostKeyAlgorithm.SSH_ED25519.value.as_markdown(), 'ssh-ed25519')
        self.assertEqual(SshCompressionAlgorithm.ZLIB_OPENSSH_COM.value.as_markdown(), 'zlib@openssh.com')
