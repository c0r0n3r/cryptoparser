#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import enum

from cryptoparser.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from cryptoparser.common.base import JSONSerializable, StringEnumParsable, StringEnumComposer


EncryptionAlgorithmParams = collections.namedtuple(
    'EncryptionAlgorithmParams',
    [
        'code',
        'cipher',
        'mode',
    ]
)

MACParams = collections.namedtuple(
    'MACParams',
    [
        'code',
        'size',
        'mac',
        'mode',
    ]
)


MACModeParams = collections.namedtuple(
    'MACModeParams',
    [
        'code',
    ]
)


KexAlgorithmParams = collections.namedtuple(
    'KexAlgorithmParams',
    [
        'code',
        'kex',
        'key_size',
    ]
)

HostKeyAlgorithmParams = collections.namedtuple(
    'HostKeyAlgorithmParams',
    [
        'code',
        'key_type',
        'authentication',
    ]
)

CompressionParams = collections.namedtuple(
    'CompressionParams',
    [
        'code',
    ]
)


class SshEncryptionAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshEncryptionAlgorithms


class SshEncryptionAlgorithms(JSONSerializable, StringEnumComposer, enum.Enum):
    ACSS_OPENSSH_ORG = EncryptionAlgorithmParams(
        code='acss@openssh.org',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CBC,
    )
    AES128_CBC = EncryptionAlgorithmParams(
        code='aes128-cbc',
        cipher=BlockCipher.ACSS,
        mode=None,  # FIXME
    )
    AES128_CTR = EncryptionAlgorithmParams(
        code='aes128-ctr',
        cipher=BlockCipher.AES_128,
        mode=BlockCipherMode.CTR,
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
    BLOWFISH_CTR = EncryptionAlgorithmParams(
        code='blowfish-ctr',
        cipher=BlockCipher.BLOWFISH,
        mode=BlockCipherMode.CTR,
    )
    CAST128_CBC = EncryptionAlgorithmParams(
        code='cast128-cbc',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CBC,
    )
    CAST128_12_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='cast128-12-cbc@ssh.com',
        cipher=BlockCipher.CAST_128,
        mode=BlockCipherMode.CBC,
    )
    CAST256_CBC = EncryptionAlgorithmParams(
        code='cast256-cbc',
        cipher=BlockCipher.CAST_256,
        mode=BlockCipherMode.CBC,
    )
    CHACHA20_POLY1305_OPENSSH_COM = EncryptionAlgorithmParams(
        code='chacha20-poly1305@openssh.com',
        cipher=BlockCipher.CHACHA20,
        mode=BlockCipherMode.POLY1305,
    )
    CRYPTICORE128_SSH_COM = EncryptionAlgorithmParams(
        code='crypticore128@ssh.com',
        cipher=BlockCipher.CRYPTICORE128,
        mode=None,
    )
    DES_CBC_SSH_COM = EncryptionAlgorithmParams(
        code='des-cbc@ssh.com',
        cipher=BlockCipher.DES,
        mode=BlockCipherMode.CBC,
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
    TRIPLE_DES_CBC = EncryptionAlgorithmParams(
        code='3des-cbc',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CBC,
    )
    TRIPLE_DES_CTR = EncryptionAlgorithmParams(
        code='3des-ctr',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CTR,
    )
    TWOFISH_CBC = EncryptionAlgorithmParams(
        code='twofish-cbc',
        cipher=BlockCipher.TWOFISH256,
        mode=BlockCipherMode.CBC,
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


class SshMacAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshMacAlgorithms


class SshMacAlgorithms(JSONSerializable, StringEnumComposer, enum.Enum):
    NONE = MACParams(
        code='none',
        size=None,
        mac=None,
        mode=None
    )
    CRYPTICORE_MAC_SSH_COM = MACParams(
        code='crypticore-mac@ssh.com',
        size=MAC.CRYPTICORE.value.digest_size,
        mac=MAC.CRYPTICORE,
        mode=MACMode.ENCRYPT_AND_MAC,  # FIXME
    )
    HMAC_SHA1 = MACParams(
        code='hmac-sha1',
        size=MAC.SHA1.value.digest_size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1_96 = MACParams(
        code='hmac-sha1-96',
        size=MAC.SHA1.value.digest_size,
        mac=96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256 = MACParams(
        code='hmac-sha2-256',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256_96 = MACParams(
        code='hmac-sha2-256-96',
        size=MAC.SHA2_256.value.digest_size,
        mac=MAC.SHA2_256,
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
        size=MAC.SHA2_512.value.digest_size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_AND_MAC,
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
    UMAC_64_OPENSSH_COM = MACParams(
        code='umac-64@openssh.com',
        size=MAC.UMAC_64.value.digest_size,
        mac=MAC.UMAC_64,
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
        mac=96,
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
    HMAC_RIPEMD160 = MACParams(
        code='hmac-ripemd160',
        size=MAC.RIPEMD160.value.digest_size,
        mac=MAC.RIPEMD160,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_RIPEMD160_96 = MACParams(
        code='hmac-ripemd160-96',
        size=MAC.RIPEMD160.value.digest_size,  # FIXME
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


class SshKexAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshKexAlgorithms


class SshKexAlgorithms(JSONSerializable, StringEnumComposer, enum.Enum):
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
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256_WIN7_MICROSOFT_COM = KexAlgorithmParams(
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


class SshHostKeyAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshHostKeyAlgorithms


class SshHostKeyAlgorithms(StringEnum, enum.Enum):
    SSH_ED25519 = HostKeyAlgorithmParams(
        code='ssh-ed25519',
        authentication=Authentication.EDDSA,
    )
    SSH_ED25519_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-ed25519-cert-v01@openssh.com',
        authentication=Authentication.EDDSA,
    )
    SSH_RSA = HostKeyAlgorithmParams(
        code='ssh-rsa',
        authentication=Authentication.RSA,
    )
    RSA_SHA2_256 = HostKeyAlgorithmParams(
        code='rsa-sha2-256',
        authentication=Authentication.RSA,
    )
    RSA_SHA2_512 = HostKeyAlgorithmParams(
        code='rsa-sha2-512',
        authentication=Authentication.RSA,
    )
    SSH_DSS = HostKeyAlgorithmParams(
        code='ssh-dss',
        authentication=Authentication.DSS,
    )
    ECDSA_SHA2_NISTP256 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp256',
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP384 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp384',
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP521 = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp521',
        authentication=Authentication.ECDSA,
    )
    SSH_RSA_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-cert-v01@openssh.com',
        authentication=Authentication.RSA,
    )
    SSH_DSS_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-dss-cert-v01@openssh.com',
        authentication=Authentication.DSS,
    )
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp256-cert-v01@openssh.com',
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp384-cert-v01@openssh.com',
        authentication=Authentication.ECDSA,
    )
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ecdsa-sha2-nistp521-cert-v01@openssh.com',
        authentication=Authentication.ECDSA,
    )


class SshCompressionAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshCompressionAlgorithms


class SshCompressionAlgorithms(JSONSerializable, StringEnumComposer, enum.Enum):
    ZLIB_OPENSSH_COM = CompressionParams(
        code='zlib@openssh.com',
    )
    ZLIB = CompressionParams(
        code='zlib',
    )
    NONE = CompressionParams(
        code='none',
    )
