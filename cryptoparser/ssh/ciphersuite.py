# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import enum
import attr

from cryptoparser.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from cryptoparser.common.base import Serializable, StringEnumParsable


@attr.s
class SshAlgorithmParamBase(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(str))

    def _as_markdown(self, level):
        return self._markdown_result(self.code, level)


@attr.s
class MACModeParams(SshAlgorithmParamBase):
    pass


class MACMode(enum.Enum):
    ENCRYPT_THEN_MAC = MACModeParams(
        code='encrypt_then_mac',
    )
    ENCRYPT_AND_MAC = MACModeParams(
        code='encrypt_and_mac',
    )
    MAC_THEN_ENCRYP = MACModeParams(
        code='mac_then_encrypt',
    )


@attr.s
class EncryptionAlgorithmParams(SshAlgorithmParamBase):
    cipher = attr.ib(validator=attr.validators.optional(attr.validators.in_(BlockCipher)))
    mode = attr.ib(validator=attr.validators.optional(attr.validators.in_(BlockCipherMode)))


@attr.s
class MACParams(SshAlgorithmParamBase):
    size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    mac = attr.ib(validator=attr.validators.optional(attr.validators.in_(MAC)))
    mode = attr.ib(validator=attr.validators.optional(attr.validators.in_(MACMode)))


@attr.s
class KexAlgorithmParams(SshAlgorithmParamBase):
    kex = attr.ib(validator=attr.validators.optional(attr.validators.in_(KeyExchange)))
    key_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


SshHostKeyType = enum.Enum('SshHostKeyType', 'KEY CERTIFICATE PGP_KEY SPKI_KEY X509_CERTIFICATE')


@attr.s
class HostKeyAlgorithmParams(SshAlgorithmParamBase):
    key_type = attr.ib(validator=attr.validators.in_(SshHostKeyType))
    authentication = attr.ib(validator=attr.validators.optional(attr.validators.in_(Authentication)))


@attr.s
class CompressionParams(SshAlgorithmParamBase):
    pass


class SshEncryptionAlgorithm(StringEnumParsable, enum.Enum):
    NONE = EncryptionAlgorithmParams(
        code='none',
        cipher=None,
        mode=None,
    )
    ACSS_OPENSSH_ORG = EncryptionAlgorithmParams(
        code='acss@openssh.org',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CBC,
    )
    AES128_CBC = EncryptionAlgorithmParams(
        code='aes128-cbc',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CBC,
    )
    AES128_CTR = EncryptionAlgorithmParams(
        code='aes128-ctr',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CTR,
    )
    AES128_GCM = EncryptionAlgorithmParams(
        code='aes128-gcm',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.GCM,
    )
    AES128_GCM_OPENSSH_COM = EncryptionAlgorithmParams(
        code='aes128-gcm@openssh.com',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.GCM,
    )
    AES192_CBC = EncryptionAlgorithmParams(
        code='aes192-cbc',
        cipher=BlockCipher.AES_192,
        mode=BlockCipherMode.CBC,
    )
    AES192_CTR = EncryptionAlgorithmParams(
        code='aes192-ctr',
        cipher=BlockCipher.AES_192,
        mode=BlockCipherMode.CTR,
    )
    AES256_CBC = EncryptionAlgorithmParams(
        code='aes256-cbc',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CBC,
    )
    AES256_CTR = EncryptionAlgorithmParams(
        code='aes256-ctr',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CTR,
    )
    AES256_GCM_OPENSSH_COM = EncryptionAlgorithmParams(
        code='aes256-gcm@openssh.com',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.GCM,
    )
    ARCFOUR = EncryptionAlgorithmParams(
        code='arcfour',
        cipher=BlockCipher.RC4_40,
        mode=None,
    )
    ARCFOUR128 = EncryptionAlgorithmParams(
        code='arcfour128',
        cipher=BlockCipher.RC4_128,
        mode=None,
    )
    ARCFOUR256 = EncryptionAlgorithmParams(
        code='arcfour256',
        cipher=BlockCipher.RC4_256,
        mode=None,
    )
    BLOWFISH_CBC = EncryptionAlgorithmParams(
        code='blowfish-cbc',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.CBC,
    )
    BLOWFISH_CFB = EncryptionAlgorithmParams(
        code='blowfish-cfb',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.CFB,
    )
    BLOWFISH_CTR = EncryptionAlgorithmParams(
        code='blowfish-ctr',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.CTR,
    )
    BLOWFISH_ECB = EncryptionAlgorithmParams(
        code='blowfish-ecb',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.ECB,
    )
    BLOWFISH_OFB = EncryptionAlgorithmParams(
        code='blowfish-ofb',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.OFB,
    )
    CAST128_CBC = EncryptionAlgorithmParams(
        code='cast128-cbc',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CBC,
    )
    CAST128_CFB = EncryptionAlgorithmParams(
        code='cast128-cfb',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CFB,
    )
    CAST128_CTR = EncryptionAlgorithmParams(
        code='cast128-ctr',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CTR,
    )
    CAST128_ECB = EncryptionAlgorithmParams(
        code='cast128-ecb',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.ECB,
    )
    CAST128_OFB = EncryptionAlgorithmParams(
        code='cast128-ofb',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.OFB,
    )
    CAST128_12_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='cast128-12-cbc@ssh.com',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CBC,
    )
    CAST128_12_CFB_SSH_COM = EncryptionAlgorithmParams(
        code='cast128-12-cfb@ssh.com',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CFB,
    )
    CAST128_12_ECB_SSH_COM = EncryptionAlgorithmParams(
        code='cast128-12-ecb@ssh.com',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.ECB,
    )
    CAST128_12_OFB_SSH_COM = EncryptionAlgorithmParams(
        code='cast128-12-ofb@ssh.com',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.OFB,
    )
    CAST256_CBC = EncryptionAlgorithmParams(
        code='cast256-cbc',
        cipher=BlockCipher.CAST_256,
        mode=BlockCipherMode.CBC,
    )
    CHACHA20_POLY1305_OPENSSH_COM = EncryptionAlgorithmParams(
        code='chacha20-poly1305@openssh.com',
        cipher=BlockCipher.CHACHA20,
        mode=None,
    )
    CRYPTICORE128_SSH_COM = EncryptionAlgorithmParams(
        code='crypticore128@ssh.com',
        cipher=BlockCipher.CRYPTICORE,
        mode=None,
    )
    DES_CBC = EncryptionAlgorithmParams(
        code='des-cbc',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.CBC,
    )
    DES_CFB = EncryptionAlgorithmParams(
        code='des-cfb',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.CFB,
    )
    DES_CTR = EncryptionAlgorithmParams(
        code='des-ctr',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.CTR,
    )
    DES_ECB = EncryptionAlgorithmParams(
        code='des-ecb',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.ECB,
    )
    DES_OFB = EncryptionAlgorithmParams(
        code='des-ofb',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.OFB,
    )
    DES_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='des-cbc@ssh.com',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.CBC,
    )
    GRASSHOPPER_CBC = EncryptionAlgorithmParams(
        code='grasshopper-cbc',
        cipher=BlockCipher.GOST_R3412_15_128,
        mode=BlockCipherMode.CBC,
    )
    GRASSHOPPER_CTR = EncryptionAlgorithmParams(
        code='grasshopper-ctr',
        cipher=BlockCipher.GOST_R3412_15_128,
        mode=BlockCipherMode.CTR,
    )
    GOST89 = EncryptionAlgorithmParams(
        code='gost89',
        cipher=BlockCipher.GOST2814789,
        mode=BlockCipherMode.CBC,
    )
    GOST89_CNT = EncryptionAlgorithmParams(
        code='gost89-cnt',
        cipher=BlockCipher.GOST2814789,
        mode=BlockCipherMode.CNT,
    )
    IDEA_CFB = EncryptionAlgorithmParams(
        code='idea-cfb',
        cipher=BlockCipher.IDEA,
        mode=BlockCipherMode.CFB,
    )
    IDEA_CTR = EncryptionAlgorithmParams(
        code='idea-ctr',
        cipher=BlockCipher.IDEA,
        mode=BlockCipherMode.CTR,
    )
    RC2_CBC = EncryptionAlgorithmParams(
        code='rc2-cbc',
        cipher=BlockCipher.RC2,
        mode=BlockCipherMode.CBC,
    )
    RC2_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='rc2-cbc@ssh.com',
        cipher=BlockCipher.RC2,
        mode=BlockCipherMode.CBC,
    )
    RC2_CTR = EncryptionAlgorithmParams(
        code='rc2-ctr',
        cipher=BlockCipher.RC2,
        mode=BlockCipherMode.CTR,
    )
    RIJNDAEL128_CBC = EncryptionAlgorithmParams(
        code='rijndael128-cbc',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CBC,
    )
    RIJNDAEL192_CBC = EncryptionAlgorithmParams(
        code='rijndael192-cbc',
        cipher=BlockCipher.AES_192,
        mode=BlockCipherMode.CBC,
    )
    RIJNDAEL256_CBC = EncryptionAlgorithmParams(
        code='rijndael256-cbc',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CBC,
    )
    RIJNDAEL_CBC_LYSATOR_LIU_SE = EncryptionAlgorithmParams(
        code='rijndael-cbc@lysator.liu.se',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CBC,
    )
    RIJNDAEL_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='rijndael-cbc@ssh.com',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CBC,
    )
    SEED_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='seed-cbc@ssh.com',
        cipher=BlockCipher.SEED,
        mode=BlockCipherMode.CBC,
    )
    SERPENT128_CBC = EncryptionAlgorithmParams(
        code='serpent128-cbc',
        cipher=BlockCipher.SERPENT_128,
        mode=BlockCipherMode.CBC,
    )
    SERPENT128_CTR = EncryptionAlgorithmParams(
        code='serpent128-ctr',
        cipher=BlockCipher.SERPENT_128,
        mode=BlockCipherMode.CTR,
    )
    SERPENT192_CBC = EncryptionAlgorithmParams(
        code='serpent192-cbc',
        cipher=BlockCipher.SERPENT_192,
        mode=BlockCipherMode.CBC,
    )
    SERPENT192_CTR = EncryptionAlgorithmParams(
        code='serpent192-ctr',
        cipher=BlockCipher.SERPENT_192,
        mode=BlockCipherMode.CTR,
    )
    SERPENT256_CBC = EncryptionAlgorithmParams(
        code='serpent256-cbc',
        cipher=BlockCipher.SERPENT_256,
        mode=BlockCipherMode.CBC,
    )
    SERPENT256_CTR = EncryptionAlgorithmParams(
        code='serpent256-ctr',
        cipher=BlockCipher.SERPENT_256,
        mode=BlockCipherMode.CTR,
    )
    TRIPLE_DES_CBC = EncryptionAlgorithmParams(
        code='3des-cbc',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CBC,
    )
    TRIPLE_DES_CFB = EncryptionAlgorithmParams(
        code='3des-cfb',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CFB,
    )
    TRIPLE_DES_CTR = EncryptionAlgorithmParams(
        code='3des-ctr',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CTR,
    )
    TRIPLE_DES_ECB = EncryptionAlgorithmParams(
        code='3des-ecb',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.ECB,
    )
    TRIPLE_DES_OFB = EncryptionAlgorithmParams(
        code='3des-ofb',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.OFB,
    )
    TWOFISH_CBC = EncryptionAlgorithmParams(
        code='twofish-cbc',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CBC,
    )
    TWOFISH_CFB = EncryptionAlgorithmParams(
        code='twofish-cfb',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CFB,
    )
    TWOFISH_CTR = EncryptionAlgorithmParams(
        code='twofish-ctr',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CTR,
    )
    TWOFISH_ECB = EncryptionAlgorithmParams(
        code='twofish-ecb',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.ECB,
    )
    TWOFISH_OFB = EncryptionAlgorithmParams(
        code='twofish-ofb',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.OFB,
    )
    TWOFISH128_CBC = EncryptionAlgorithmParams(
        code='twofish128-cbc',
        cipher=BlockCipher.TWOFISH128,
        mode=BlockCipherMode.CBC,
    )
    TWOFISH128_CTR = EncryptionAlgorithmParams(
        code='twofish128-ctr',
        cipher=BlockCipher.TWOFISH128,
        mode=BlockCipherMode.CTR,
    )
    TWOFISH192_CBC = EncryptionAlgorithmParams(
        code='twofish192-cbc',
        cipher=BlockCipher.TWOFISH192,
        mode=BlockCipherMode.CBC,
    )
    TWOFISH192_CTR = EncryptionAlgorithmParams(
        code='twofish192-ctr',
        cipher=BlockCipher.TWOFISH192,
        mode=BlockCipherMode.CTR,
    )
    TWOFISH256_CBC = EncryptionAlgorithmParams(
        code='twofish256-cbc',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CBC,
    )
    TWOFISH256_CTR = EncryptionAlgorithmParams(
        code='twofish256-ctr',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CTR,
    )


class SshMacAlgorithm(StringEnumParsable, enum.Enum):
    NONE = MACParams(
        code='none',
        size=None,
        mac=None,
        mode=None
    )
    AEAD_AES_128_CCM = MACParams(
        code='AEAD_AES_128_CCM',
        size=MAC.AEAD_AES_128_CCM.value.digest_size,
        mac=MAC.AEAD_AES_128_CCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_128_CCM_SSH = MACParams(
        code='aead-aes-128-ccm-ssh',
        size=MAC.AEAD_AES_128_CCM.value.digest_size,
        mac=MAC.AEAD_AES_128_CCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_256_CCM = MACParams(
        code='AEAD_AES_256_CCM',
        size=MAC.AEAD_AES_256_CCM.value.digest_size,
        mac=MAC.AEAD_AES_256_CCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_256_CCM_SSH = MACParams(
        code='aead-aes-256-ccm-ssh',
        size=MAC.AEAD_AES_256_CCM.value.digest_size,
        mac=MAC.AEAD_AES_256_CCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_128_GCM = MACParams(
        code='AEAD_AES_128_GCM',
        size=MAC.AEAD_AES_128_GCM.value.digest_size,
        mac=MAC.AEAD_AES_128_GCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_128_GCM_SSH = MACParams(
        code='aead-aes-128-gcm-ssh',
        size=MAC.AEAD_AES_128_GCM.value.digest_size,
        mac=MAC.AEAD_AES_128_GCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_256_GCM = MACParams(
        code='AEAD_AES_256_GCM',
        size=MAC.AEAD_AES_256_GCM.value.digest_size,
        mac=MAC.AEAD_AES_256_GCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    AEAD_AES_256_GCM_SSH = MACParams(
        code='aead-aes-256-gcm-ssh',
        size=MAC.AEAD_AES_256_GCM.value.digest_size,
        mac=MAC.AEAD_AES_256_GCM,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    CRYPTICORE_MAC_SSH_COM = MACParams(
        code='crypticore-mac@ssh.com',
        size=MAC.CRYPTICORE.value.digest_size,
        mac=MAC.CRYPTICORE,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_GOST2012_256_ETM = MACParams(
        code='hmac-gost2012-256-etm',
        size=MAC.GOST_R3411_12_256.value.digest_size,
        mac=MAC.GOST_R3411_12_256,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_GOSTHASH = MACParams(
        code='hmac-gosthash',
        size=MAC.GOST_R3411_94.value.digest_size,
        mac=MAC.GOST_R3411_94,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_GOSTHASH2012_256 = MACParams(
        code='hmac-gosthash2012-256',
        size=MAC.GOST_R3411_12_256.value.digest_size,
        mac=MAC.GOST_R3411_12_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )

    HMAC_SHA256 = MACParams(
        code='hmac-sha256',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1 = MACParams(
        code='hmac-sha1',
        size=MAC.SHA1.value.digest_size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1_96 = MACParams(
        code='hmac-sha1-96',
        size=96,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_224 = MACParams(
        code='hmac-sha2-224',
        size=MAC.SHA2_224.value.digest_size,
        mac=MAC.SHA2_224,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256 = MACParams(
        code='hmac-sha2-256',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA256_96_SSH_COM = MACParams(
        code='hmac-sha256-96@ssh.com',
        size=96,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256_96 = MACParams(
        code='hmac-sha2-256-96',
        size=96,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-256-96-etm@openssh.com',
        size=96,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA2_384 = MACParams(
        code='hmac-sha2-384',
        size=MAC.SHA2_384.value.digest_size,
        mac=MAC.SHA2_384,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_512 = MACParams(
        code='hmac-sha2-512',
        size=MAC.SHA2_512.value.digest_size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_512_96 = MACParams(
        code='hmac-sha2-512-96',
        size=96,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA3_224 = MACParams(
        code='hmac-sha3-224',
        size=224,
        mac=MAC.SHA3_224,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA3_256 = MACParams(
        code='hmac-sha3-256',
        size=256,
        mac=MAC.SHA3_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA3_384 = MACParams(
        code='hmac-sha3-384',
        size=384,
        mac=MAC.SHA3_384,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA3_512 = MACParams(
        code='hmac-sha3-512',
        size=512,
        mac=MAC.SHA3_512,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_512_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-512-96-etm@openssh.com',
        size=96,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA224_SSH_COM = MACParams(
        code='hmac-sha224@ssh.com',
        size=MAC.SHA2_224.value.digest_size,
        mac=MAC.SHA2_224,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA256_SSH_COM = MACParams(
        code='hmac-sha256@ssh.com',
        size=128,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA384_SSH_COM = MACParams(
        code='hmac-sha384@ssh.com',
        size=MAC.SHA2_384.value.digest_size,
        mac=MAC.SHA2_384,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA512_SSH_COM = MACParams(
        code='hmac-sha512@ssh.com',
        size=MAC.SHA2_512.value.digest_size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256_2_SSH_COM = MACParams(
        code='hmac-sha256-2@ssh.com',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_MD5 = MACParams(
        code='hmac-md5',
        size=MAC.MD5.value.digest_size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_MD5_96 = MACParams(
        code='hmac-md5-96',
        size=MAC.MD5.value.digest_size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_32_OPENSSH_COM = MACParams(
        code='umac-32@openssh.com',
        size=MAC.UMAC_32.value.digest_size,
        mac=MAC.UMAC_32,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_64_OPENSSH_COM = MACParams(
        code='umac-64@openssh.com',
        size=MAC.UMAC_64.value.digest_size,
        mac=MAC.UMAC_64,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_96_OPENSSH_COM = MACParams(
        code='umac-96@openssh.com',
        size=MAC.UMAC_96.value.digest_size,
        mac=MAC.UMAC_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_128_OPENSSH_COM = MACParams(
        code='umac-128@openssh.com',
        size=MAC.UMAC_128.value.digest_size,
        mac=MAC.UMAC_128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha1-etm@openssh.com',
        size=MAC.SHA1.value.digest_size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA1_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha1-96-etm@openssh.com',
        size=MAC.SHA1.value.digest_size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA2_256_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-256-etm@openssh.com',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA2_512_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-512-etm@openssh.com',
        size=MAC.SHA2_512.value.digest_size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_MD5_ETM_OPENSSH_COM = MACParams(
        code='hmac-md5-etm@openssh.com',
        size=MAC.MD5.value.digest_size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_MD5_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-md5-96-etm@openssh.com',
        size=MAC.MD5.value.digest_size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_RIPEMD = MACParams(
        code='hmac-ripemd',
        size=MAC.RIPEMD128.value.digest_size,
        mac=MAC.RIPEMD128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160 = MACParams(
        code='hmac-ripemd160',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_SSH_COM = MACParams(
        code='hmac-ripemd160@ssh.com',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_96 = MACParams(
        code='hmac-ripemd160-96',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_96_SSH_COM = MACParams(
        code='hmac-ripemd160-96@ssh.com',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_OPENSSH_COM = MACParams(
        code='hmac-ripemd160@openssh.com',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_ETM_OPENSSH_COM = MACParams(
        code='hmac-ripemd160-etm@openssh.com',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_TIGER128 = MACParams(
        code='hmac-tiger128',
        size=MAC.TIGER_128.value.digest_size,
        mac=MAC.TIGER_128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER128_96 = MACParams(
        code='hmac-tiger128-96',
        size=MAC.TIGER_128_96.value.digest_size,
        mac=MAC.TIGER_128_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER128_SSH_COM = MACParams(
        code='hmac-tiger128@ssh.com',
        size=MAC.TIGER_128.value.digest_size,
        mac=MAC.TIGER_128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER128_96_SSH_COM = MACParams(
        code='hmac-tiger128-96@ssh.com',
        size=MAC.TIGER_128_96.value.digest_size,
        mac=MAC.TIGER_128_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER160 = MACParams(
        code='hmac-tiger160',
        size=MAC.TIGER_160.value.digest_size,
        mac=MAC.TIGER_160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER160_96 = MACParams(
        code='hmac-tiger160-96',
        size=MAC.TIGER_160_96.value.digest_size,
        mac=MAC.TIGER_160_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER160_SSH_COM = MACParams(
        code='hmac-tiger160@ssh.com',
        size=MAC.TIGER_160.value.digest_size,
        mac=MAC.TIGER_160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER160_96_SSH_COM = MACParams(
        code='hmac-tiger160-96@ssh.com',
        size=MAC.TIGER_160_96.value.digest_size,
        mac=MAC.TIGER_160_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER192 = MACParams(
        code='hmac-tiger192',
        size=MAC.TIGER_192.value.digest_size,
        mac=MAC.TIGER_192,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER192_96 = MACParams(
        code='hmac-tiger192-96',
        size=MAC.TIGER_192_96.value.digest_size,
        mac=MAC.TIGER_192_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER192_SSH_COM = MACParams(
        code='hmac-tiger192@ssh.com',
        size=MAC.TIGER_192.value.digest_size,
        mac=MAC.TIGER_192,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_TIGER192_96_SSH_COM = MACParams(
        code='hmac-tiger192-96@ssh.com',
        size=MAC.TIGER_192_96.value.digest_size,
        mac=MAC.TIGER_192_96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_WHIRLPOOL = MACParams(
        code='hmac-whirlpool',
        size=MAC.WHIRLPOOL.value.digest_size,
        mac=MAC.WHIRLPOOL,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_64_ETM_OPENSSH_COM = MACParams(
        code='umac-64-etm@openssh.com',
        size=MAC.UMAC_64.value.digest_size,
        mac=MAC.UMAC_64,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    UMAC_128_ETM_OPENSSH_COM = MACParams(
        code='umac-128-etm@openssh.com',
        size=MAC.UMAC_128.value.digest_size,
        mac=MAC.UMAC_128,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    TIGER128 = MACParams(
        code='tiger128',
        size=MAC.TIGER_128.value.digest_size,
        mac=MAC.TIGER_128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    TIGER160 = MACParams(
        code='tiger160',
        size=MAC.TIGER_160.value.digest_size,
        mac=MAC.TIGER_160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    TIGER192 = MACParams(
        code='tiger192',
        size=MAC.TIGER_192.value.digest_size,
        mac=MAC.TIGER_192,
        mode=MACMode.ENCRYPT_AND_MAC,
    )


class SshKexAlgorithm(StringEnumParsable, enum.Enum):
    DIFFIE_HELLMAN_GROUP1_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group1-sha1',
        kex=KeyExchange.DHE,
        key_size=1024,
    )
    DIFFIE_HELLMAN_GROUP1_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group1-sha256',
        kex=KeyExchange.DHE,
        key_size=1024,
    )
    DIFFIE_HELLMAN_GROUP1_SHA1_WIN7_MICROSOFT_COM = KexAlgorithmParams(
        code='diffie-hellman-group1-sha1-win7@microsoft.com',
        kex=KeyExchange.DHE,
        key_size=1024,
    )
    DIFFIE_HELLMAN_GROUP14_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group14-sha1',
        kex=KeyExchange.DHE,
        key_size=2048,
    )

    DIFFIE_HELLMAN_GROUP1_SHA14_WIN7_MICROSOFT_COM = KexAlgorithmParams(
        code='diffie-hellman-group14-sha1-win7@microsoft.com',
        kex=KeyExchange.DHE,
        key_size=2048,
    )
    DIFFIE_HELLMAN_GROUP14_SHA224_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group14-sha224@ssh.com',
        kex=KeyExchange.DHE,
        key_size=2048,
    )
    DIFFIE_HELLMAN_GROUP14_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group14-sha256',
        kex=KeyExchange.DHE,
        key_size=2048,
    )
    DIFFIE_HELLMAN_GROUP14_SHA256_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group14-sha256@ssh.com',
        kex=KeyExchange.DHE,
        key_size=2048,
    )
    DIFFIE_HELLMAN_GROUP15_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group15-sha256',
        kex=KeyExchange.DHE,
        key_size=3072,
    )
    DIFFIE_HELLMAN_GROUP15_SHA256_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group15-sha256@ssh.com',
        kex=KeyExchange.DHE,
        key_size=3072,
    )
    DIFFIE_HELLMAN_GROUP15_SHA384_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group15-sha384@ssh.com',
        kex=KeyExchange.DHE,
        key_size=3072,
    )
    DIFFIE_HELLMAN_GROUP15_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group15-sha512',
        kex=KeyExchange.DHE,
        key_size=3072,
    )
    DIFFIE_HELLMAN_GROUP16_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group16-sha256',
        kex=KeyExchange.DHE,
        key_size=4096,
    )
    DIFFIE_HELLMAN_GROUP16_SHA384_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group16-sha384@ssh.com',
        kex=KeyExchange.DHE,
        key_size=4096,
    )
    DIFFIE_HELLMAN_GROUP16_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group16-sha512',
        kex=KeyExchange.DHE,
        key_size=4096,
    )
    DIFFIE_HELLMAN_GROUP16_SHA512_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group16-sha512@ssh.com',
        kex=KeyExchange.DHE,
        key_size=4096,
    )
    DIFFIE_HELLMAN_GROUP17_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group17-sha512',
        kex=KeyExchange.DHE,
        key_size=6144,
    )
    DIFFIE_HELLMAN_GROUP18_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group18-sha512',
        kex=KeyExchange.DHE,
        key_size=8192,
    )
    DIFFIE_HELLMAN_GROUP18_SHA512_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group18-sha512@ssh.com',
        kex=KeyExchange.DHE,
        key_size=8192,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha1',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha256',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256_WIN7_MICROSOFT_COM = KexAlgorithmParams(  # pylint: disable=invalid-name
        code='diffie-hellman-group-exchange-sha256-win7@microsoft.com',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha512',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA224_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha224@ssh.com',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA384_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha384@ssh.com',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA512_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha512@ssh.com',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    ECDH_SHA2_1_3_132_0_10 = KexAlgorithmParams(
        code='ecdh-sha2-1.3.132.0.10',
        kex=KeyExchange.ECDHE,
        key_size=256,
    )
    ECDH_SHA2_BRAINPOOLP256R1_GENUA_DE = KexAlgorithmParams(
        code='ecdh-sha2-brainpoolp256r1@genua.de',
        kex=KeyExchange.ECDHE,
        key_size=256,
    )
    ECDH_SHA2_BRAINPOOLP384R1_GENUA_DE = KexAlgorithmParams(
        code='ecdh-sha2-brainpoolp384r1@genua.de',
        kex=KeyExchange.ECDHE,
        key_size=384,
    )
    ECDH_SHA2_BRAINPOOLP521R1_GENUA_DE = KexAlgorithmParams(
        code='ecdh-sha2-brainpoolp521r1@genua.de',
        kex=KeyExchange.ECDHE,
        key_size=521,
    )
    ECDH_SHA2_CURVE25519 = KexAlgorithmParams(
        code='ecdh-sha2-curve25519',
        kex=KeyExchange.ECDHE,
        key_size=255,
    )
    ECDH_SHA2_NISTB233 = KexAlgorithmParams(
        code='ecdh-sha2-nistb233',
        kex=KeyExchange.ECDHE,
        key_size=233,
    )
    ECDH_SHA2_NISTB409 = KexAlgorithmParams(
        code='ecdh-sha2-nistb409',
        kex=KeyExchange.ECDHE,
        key_size=409,
    )
    ECDH_SHA2_NISTK163 = KexAlgorithmParams(
        code='ecdh-sha2-nistk163',
        kex=KeyExchange.ECDHE,
        key_size=163,
    )
    ECDH_SHA2_NISTK233 = KexAlgorithmParams(
        code='ecdh-sha2-nistk233',
        kex=KeyExchange.ECDHE,
        key_size=233,
    )
    ECDH_SHA2_NISTK283 = KexAlgorithmParams(
        code='ecdh-sha2-nistk283',
        kex=KeyExchange.ECDHE,
        key_size=283,
    )
    ECDH_SHA2_NISTK409 = KexAlgorithmParams(
        code='ecdh-sha2-nistk409',
        kex=KeyExchange.ECDHE,
        key_size=409,
    )
    ECDH_SHA2_NISTP192 = KexAlgorithmParams(
        code='ecdh-sha2-nistp192',
        kex=KeyExchange.ECDHE,
        key_size=192,
    )
    ECDH_SHA2_NISTP224 = KexAlgorithmParams(
        code='ecdh-sha2-nistp224',
        kex=KeyExchange.ECDHE,
        key_size=224,
    )
    ECDH_SHA2_NISTP256 = KexAlgorithmParams(
        code='ecdh-sha2-nistp256',
        kex=KeyExchange.ECDHE,
        key_size=256,
    )
    ECDH_SHA2_NISTP256_WIN7_MICROSOFT_COM = KexAlgorithmParams(
        code='ecdh-sha2-nistp256-win7@microsoft.com',
        kex=KeyExchange.ECDHE,
        key_size=256,
    )
    ECDH_SHA2_NISTP384 = KexAlgorithmParams(
        code='ecdh-sha2-nistp384',
        kex=KeyExchange.ECDHE,
        key_size=384,
    )
    ECDH_SHA2_NISTP384_WIN7_MICROSOFT_COM = KexAlgorithmParams(
        code='ecdh-sha2-nistp384-win7@microsoft.com',
        kex=KeyExchange.ECDHE,
        key_size=384,
    )
    ECDH_SHA2_NISTP521 = KexAlgorithmParams(
        code='ecdh-sha2-nistp521',
        kex=KeyExchange.ECDHE,
        key_size=521,
    )
    ECDH_SHA2_NISTP521_WIN7_MICROSOFT_COM = KexAlgorithmParams(
        code='ecdh-sha2-nistp521-win7@microsoft.com',
        kex=KeyExchange.ECDHE,
        key_size=521,
    )
    ECDH_SHA2_NISTT571 = KexAlgorithmParams(
        code='ecdh-sha2-nistt571',
        kex=KeyExchange.ECDHE,
        key_size=571,
    )
    ECMQV_SHA2 = KexAlgorithmParams(
        code='ecmqv-sha2',
        kex=KeyExchange.ECDHE,
        key_size=None,
    )
    CURVE25519_SHA256 = KexAlgorithmParams(
        code='curve25519-sha256',
        kex=KeyExchange.ECDHE,
        key_size=255,
    )
    CURVE25519_SHA256_LIBSSH_ORG = KexAlgorithmParams(
        code='curve25519-sha256@libssh.org',
        kex=KeyExchange.ECDHE,
        key_size=255,
    )
    CURVE448_SHA512_LIBSSH_ORG = KexAlgorithmParams(
        code='curve448-sha512',
        kex=KeyExchange.ECDHE,
        key_size=448
    )
    KEXGUESS2_MATT_UCC_ASN_AU = KexAlgorithmParams(
        code='kexguess2@matt.ucc.asn.au',
        kex=KeyExchange.DHE,
        key_size=None,
    )
    M383_SHA384_LIBASSH_ORG = KexAlgorithmParams(
        code='m383-sha384@libassh.org',
        kex=KeyExchange.ECDHE,
        key_size=383,
    )
    M511_SHA512_LIBASSH_ORG = KexAlgorithmParams(
        code='m511-sha512@libassh.org',
        kex=KeyExchange.ECDHE,
        key_size=511,
    )
    RSA1024_SHA1 = KexAlgorithmParams(
        code='rsa1024-sha1',
        kex=KeyExchange.RSA,
        key_size=1024,
    )
    RSA2048_SHA256 = KexAlgorithmParams(
        code='rsa2048-sha256',
        kex=KeyExchange.RSA,
        key_size=2048,
    )
    SNTRUP4591761X25519_SHA512_TINYSSH_ORG = KexAlgorithmParams(
        code='sntrup4591761x25519-sha512@tinyssh.org',
        kex=KeyExchange.SNTRUP_X25519,
        key_size=10000,
    )
    SNTRUP761X25519_SHA512_OPENSSH_COM = KexAlgorithmParams(
        code='sntrup761x25519-sha512@openssh.com',
        kex=KeyExchange.SNTRUP_X25519,
        key_size=9264,
    )


class SshHostKeyAlgorithm(StringEnumParsable, enum.Enum):
    SSH_ED25519 = HostKeyAlgorithmParams(
        code='ssh-ed25519',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.EDDSA,
    )
    SSH_RSA = HostKeyAlgorithmParams(
        code='ssh-rsa',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    RSA_SHA2_256 = HostKeyAlgorithmParams(
        code='rsa-sha2-256',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    RSA_SHA2_256_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='rsa-sha2-256-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    RSA_SHA2_512 = HostKeyAlgorithmParams(
        code='rsa-sha2-512',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    RSA_SHA2_512_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='rsa-sha2-512-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    SSH_DSS = HostKeyAlgorithmParams(
        code='ssh-dss',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    DSA2048_SHA224_LIBASSH_ORG = HostKeyAlgorithmParams(
        code='dsa2048-sha224@libassh.org',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    DSA2048_SHA256_LIBASSH_ORG = HostKeyAlgorithmParams(
        code='dsa2048-sha256@libassh.org',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    DSA3072_SHA256_LIBASSH_ORG = HostKeyAlgorithmParams(
        code='dsa3072-sha256@libassh.org',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    ECDSA_SHA2_1_3_132_0_10 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-1.3.132.0.10',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_1_3_132_0_10_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-1.3.132.0.10-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP256 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp256',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP384 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp384',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP521 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp521',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.ECDSA,
    )
    EDDSA_E382_SHAKE256_LIBASSH_ORG = HostKeyAlgorithmParams(
        code='eddsa-e382-shake256@libassh.org',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    EDDSA_E521_SHAKE256_LIBASSH_ORG = HostKeyAlgorithmParams(
        code='eddsa-e521-shake256@libassh.org',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SK_ECDSA_SHA2_NISTP256_OPENSSH_COM = HostKeyAlgorithmParams(
        code='sk-ecdsa-sha2-nistp256@openssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.ECDSA,
    )
    SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.ECDSA,
    )
    SK_SSH_ED25519_OPENSSH_COM = HostKeyAlgorithmParams(
        code='sk-ssh-ed25519@openssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.EDDSA,
    )
    SK_SSH_ED25519_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='sk-ssh-ed25519-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.EDDSA,
    )
    SSH_RSA_CERT_V00_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-cert-v00@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    SSH_RSA_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    SSH_RSA_SHA2_256_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha2-256-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    SSH_RSA_SHA2_512_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha2-512-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
    )
    SSH_DSS_CERT_V00_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-cert-v00@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.DSS,
    )
    SSH_DSS_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.DSS,
    )
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp256-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp384-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp521-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.ECDSA,
    )
    PGP_SIGN_DSS = HostKeyAlgorithmParams(
        code='pgp-sign-dss',
        key_type=SshHostKeyType.PGP_KEY,
        authentication=Authentication.DSS,
    )
    PGP_SIGN_RSA = HostKeyAlgorithmParams(
        code='pgp-sign-rsa',
        key_type=SshHostKeyType.PGP_KEY,
        authentication=Authentication.DSS,
    )
    SPKI_SIGN_DSS = HostKeyAlgorithmParams(
        code='spki-sign-dss',
        key_type=SshHostKeyType.SPKI_KEY,
        authentication=Authentication.DSS,
    )
    SPKI_SIGN_RSA = HostKeyAlgorithmParams(
        code='spki-sign-rsa',
        key_type=SshHostKeyType.SPKI_KEY,
        authentication=Authentication.DSS,
    )
    SSH_DSS_SHA224_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-sha224@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_DSS_SHA256_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-sha256@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_DSS_SHA384_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-sha384@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_DSS_SHA512_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-sha512@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_ED25519_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-ed25519-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.EDDSA,
    )
    SSH_ED448 = HostKeyAlgorithmParams(
        code='ssh-ed448',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_ED448_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-ed448-cert-v01@openssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
    )
    SSH_RSA_SHA224_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha224@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    SSH_RSA_SHA256_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha256@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    SSH_RSA_SHA384_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha384@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    SSH_RSA_SHA512_SSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-sha512@ssh.com',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    X509V3_ECDSA_SHA2_1_3_132_0_10 = HostKeyAlgorithmParams(
        code='x509v3-ecdsa-sha2-1.3.132.0.10',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_ECDSA_SHA2_NISTP256 = HostKeyAlgorithmParams(
        code='x509v3-ecdsa-sha2-nistp256',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_ECDSA_SHA2_NISTP384 = HostKeyAlgorithmParams(
        code='x509v3-ecdsa-sha2-nistp384',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_ECDSA_SHA2_NISTP521 = HostKeyAlgorithmParams(
        code='x509v3-ecdsa-sha2-nistp521',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_RSA2048_SHA256 = HostKeyAlgorithmParams(
        code='x509v3-rsa2048-sha256',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_DSS_SHA1 = HostKeyAlgorithmParams(
        code='x509v3-sign-dss-sha1',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_RSA = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_RSA_SHA1 = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa-sha1',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SSH_RSA = HostKeyAlgorithmParams(
        code='x509v3-ssh-rsa',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_RSA_SHA224_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa-sha224@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_RSA_SHA256_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa-sha256@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_RSA_SHA384_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa-sha384@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_RSA_SHA512_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa-sha512@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.RSA,
    )
    X509V3_SIGN_DSS = HostKeyAlgorithmParams(
        code='x509v3-sign-dss',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SSH_DSS = HostKeyAlgorithmParams(
        code='x509v3-ssh-dss',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_DSS_SHA224_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-dss-sha224@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_DSS_SHA256_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-dss-sha256@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_DSS_SHA384_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-dss-sha384@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SIGN_DSS_SHA512_SSH_COM = HostKeyAlgorithmParams(
        code='x509v3-sign-dss-sha512@ssh.com',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SSH_ED25519 = HostKeyAlgorithmParams(
        code='x509v3-ssh-ed25519',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )
    X509V3_SSH_ED448 = HostKeyAlgorithmParams(
        code='x509v3-ssh-ed448',
        key_type=SshHostKeyType.X509_CERTIFICATE,
        authentication=Authentication.DSS,
    )


class SshCompressionAlgorithm(StringEnumParsable, enum.Enum):
    ZLIB_OPENSSH_COM = CompressionParams(
        code='zlib@openssh.com',
    )
    ZLIB = CompressionParams(
        code='zlib',
    )
    NONE = CompressionParams(
        code='none',
    )
