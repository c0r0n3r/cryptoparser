#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import collections

KeyExchangeParams = collections.namedtuple('KeyExchangeParams', ['name', 'pfs', ])
AuthenticationParams = collections.namedtuple('AuthenticationParams', ['name', 'anonymous', 'exportable', ])
BlockCipherParams = collections.namedtuple('BlockCipherParams', ['name', 'key_size', 'block_size', 'exportable', ])
BlockCipherModeParams = collections.namedtuple('BlockCipherModeParams', ['name', 'aead', ])
MACParams = collections.namedtuple('MACParams', ['name', 'size', ])
NamedGroupParams = collections.namedtuple('NamedGroupParams', ['name', 'size', 'group_type', ])
CipherSuiteParams = collections.namedtuple('TlsCipherSuiteParams', ['key_exchange', ])


class KeyExchange(enum.Enum):
    DH = KeyExchangeParams(  # pylint: disable=invalid-name
        name='DH',
        pfs=False
    )
    DHE = KeyExchangeParams(
        name='DHE',
        pfs=True
    )
    ECDH = KeyExchangeParams(
        name='ECDH',
        pfs=False
    )
    ECDHE = KeyExchangeParams(
        name='ECDHE',
        pfs=True
    )
    KRB5 = KeyExchangeParams(
        name='KRB5',
        pfs=False
    )
    KRB5_EXPORT = KeyExchangeParams(
        name='KRB5_EXPORT',
        pfs=False
    )
    PSK = KeyExchangeParams(
        name='PSK',
        pfs=False
    )
    RSA = KeyExchangeParams(
        name='RSA',
        pfs=False
    )
    RSA_EXPORT = KeyExchangeParams(
        name='RSA_EXPORT',
        pfs=False
    )
    SRP = KeyExchangeParams(
        name='SRP',
        pfs=False
    )


class Authentication(enum.Enum):
    anon = AuthenticationParams(
        name='anon',
        anonymous=True,
        exportable=True,
    )
    anon_EXPORT = AuthenticationParams(
        name='anon_EXPORT',
        anonymous=True,
        exportable=False,
    )
    DSS = AuthenticationParams(
        name='DSS',
        anonymous=False,
        exportable=True,
    )
    DSS_EXPORT = AuthenticationParams(
        name='DSS_EXPORT',
        anonymous=False,
        exportable=False,
    )
    ECDSA = AuthenticationParams(
        name='ECDSA',
        anonymous=False,
        exportable=True,
    )
    EDDSA = AuthenticationParams(
        name='EdDSA',
        anonymous=False,
        exportable=False,
    )
    KRB5 = AuthenticationParams(
        name='KRB5',
        anonymous=False,
        exportable=True,
    )
    KRB5_EXPORT = AuthenticationParams(
        name='KRB5_EXPORT',
        anonymous=False,
        exportable=False,
    )
    PSK = AuthenticationParams(
        name='PSK',
        anonymous=False,
        exportable=True,
    )
    RSA = AuthenticationParams(
        name='RSA',
        anonymous=False,
        exportable=True,
    )
    RSA_EXPORT = AuthenticationParams(
        name='RSA_EXPORT',
        anonymous=False,
        exportable=False,
    )
    SRP = AuthenticationParams(
        name='SRP',
        anonymous=False,
        exportable=True,
    )


class BlockCipher(enum.Enum):
    AES_128 = BlockCipherParams(
        name='AES_128',
        key_size=128,
        block_size=128,
        exportable=True,
    )
    AES_192 = BlockCipherParams(
        name='AES_192',
        key_size=192,
        block_size=128,
        exportable=True,
    )
    AES_256 = BlockCipherParams(
        name='AES_256',
        key_size=256,
        block_size=128,
        exportable=True,
    )
    ARIA_128 = BlockCipherParams(
        name='ARIA_128',
        key_size=128,
        block_size=128,
        exportable=True,
    )
    ARIA_192 = BlockCipherParams(
        name='ARIA_192',
        key_size=192,
        block_size=128,
        exportable=True,
    )
    ARIA_256 = BlockCipherParams(
        name='ARIA_256',
        key_size=256,
        block_size=128,
        exportable=True,
    )
    BLOWFISH = BlockCipherParams(
        name='BLOWFISH',
        key_size=32,  # min
        # key_size_max=448,
        block_size=64,
        exportable=True,
    )
    CAMELLIA_128 = BlockCipherParams(
        name='CAMELLIA_128',
        key_size=128,
        block_size=128,
        exportable=True,
    )
    CAMELLIA_256 = BlockCipherParams(
        name='CAMELLIA_256',
        key_size=256,
        block_size=128,
        exportable=True,
    )
    CAST_128 = BlockCipherParams(
        name='CAST_128',
        key_size=40,  # min
        # key_size_max=128,
        block_size=64,
        exportable=True,
    )
    CAST_256 = BlockCipherParams(
        name='CAST_256',
        key_size=128,  # min
        # key_size_max=256,
        block_size=128,
        exportable=True,
    )
    CHACHA20 = BlockCipherParams(
        name='CHACHA20',
        key_size=128,  # min
        #  key_size_max=256,
        block_size=None,
        exportable=True,
    )
    DES = BlockCipherParams(
        name='DES',
        key_size=56,
        block_size=64,
        exportable=True,
    )
    DES40 = BlockCipherParams(
        name='DES40',
        key_size=40,
        block_size=64,
        exportable=True,
    )
    IDEA = BlockCipherParams(
        name='IDEA',
        key_size=64,
        block_size=64,
        exportable=True,
    )
    IDEA_128 = BlockCipherParams(
        name='IDEA_128',
        key_size=128,
        block_size=64,
        exportable=True,
    )
    RC2_40 = BlockCipherParams(
        name='RC2_40',
        key_size=40,
        block_size=64,
        exportable=True,
    )
    RC2_128 = BlockCipherParams(
        name='RC2_128',
        key_size=128,
        block_size=64,
        exportable=True,
    )
    RC2_128_EXPORT40 = BlockCipherParams(
        name='RC2_128_EXPORT40',
        key_size=40,
        block_size=64,
        exportable=True,
    )
    RC4_40 = BlockCipherParams(
        name='RC4_40',
        key_size=40,
        block_size=None,
        exportable=True,
    )
    RC4_128 = BlockCipherParams(
        name='RC4_128',
        key_size=128,
        block_size=None,
        exportable=True,
    )
    RC4_128_EXPORT40 = BlockCipherParams(
        name='RC4_128_EXPORT40',
        key_size=40,
        block_size=None,
        exportable=True,
    )
    RC4_256 = BlockCipherParams(
        name='RC4_256',
        key_size=256,
        block_size=None,
        exportable=True,
    )
    SEED = BlockCipherParams(
        name='SEED',
        key_size=128,
        block_size=128,
        exportable=True,
    )
    TRIPLE_DES = BlockCipherParams(
        name='3DES',
        key_size=128,  # min
        #  key_size_max=192,
        block_size=64,
        exportable=True,
    )
    TRIPLE_DES_EDE = BlockCipherParams(
        name='3DES_EDE',
        key_size=128,  # min
        #  key_size_max=192,
        block_size=64,
        exportable=True,
    )


class BlockCipherMode(enum.Enum):
    CBC = BlockCipherModeParams(
        name='CBC',
        aead=False
    )
    CCM = BlockCipherModeParams(
        name='CCM',
        aead=True
    )
    CCM_8 = BlockCipherModeParams(
        name='CCM_8',
        aead=True
    )
    CTR = BlockCipherModeParams(
        name='CTR',
        aead=False
    )
    GCM = BlockCipherModeParams(
        name='GCM',
        aead=True
    )
    POLY1305 = BlockCipherModeParams(
        name='POLY1305',
        aead=True
    )


class MAC(enum.Enum):
    MD5 = MACParams(
        name='MD5',
        size=64
    )
    UMAC_64 = MACParams(
        name='UMAC_64',
        size=64
    )
    UMAC_128 = MACParams(
        name='UMAC_128',
        size=128
    )
    SHA1 = MACParams(
        name='SHA1',
        size=160
    )
    SHA2_224 = MACParams(
        name='SHA2_224',
        size=224
    )
    SHA2_256 = MACParams(
        name='SHA2_256',
        size=256
    )
    SHA2_384 = MACParams(
        name='SHA2_384',
        size=384
    )
    SHA2_512 = MACParams(
        name='SHA2_512',
        size=512
    )


class NamedGroupType(enum.IntEnum):
    ELLIPTIC_CURVE = 1
    DH_PARAM = 2


class NamedGroup(enum.Enum):
    SECT163K1 = NamedGroupParams(
        name='sect163k1',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT163R1 = NamedGroupParams(
        name='sect163r1',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT163R2 = NamedGroupParams(
        name='sect163r2',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT193R1 = NamedGroupParams(
        name='sect193r1',
        size=193,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT193R2 = NamedGroupParams(
        name='sect193r2',
        size=193,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT233K1 = NamedGroupParams(
        name='sect233k1',
        size=233,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT233R1 = NamedGroupParams(
        name='sect233r1',
        size=233,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT239K1 = NamedGroupParams(
        name='sect239k1',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT283K1 = NamedGroupParams(
        name='sect283k1',
        size=283,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT283R1 = NamedGroupParams(
        name='sect283r1',
        size=283,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT409K1 = NamedGroupParams(
        name='sect409k1',
        size=409,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT409R1 = NamedGroupParams(
        name='sect409r1',
        size=409,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT571K1 = NamedGroupParams(
        name='sect571k1',
        size=571,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT571R1 = NamedGroupParams(
        name='sect571r1',
        size=571,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160K1 = NamedGroupParams(
        name='secp160k1',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160R1 = NamedGroupParams(
        name='secp160r1',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160R2 = NamedGroupParams(
        name='secp160r2',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP192K1 = NamedGroupParams(
        name='secp192k1',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP192R1 = NamedGroupParams(
        name='secp192r1',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP224K1 = NamedGroupParams(
        name='secp224k1',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP224R1 = NamedGroupParams(
        name='secp224r1',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP256K1 = NamedGroupParams(
        name='secp256k1',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP256R1 = NamedGroupParams(
        name='secp256r1',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP384R1 = NamedGroupParams(
        name='secp384r1',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP521R1 = NamedGroupParams(
        name='secp521r1',
        size=521,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )

    BRAINPOOLP160R1 = NamedGroupParams(
        name='brainpoolp160r1',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP160T1 = NamedGroupParams(
        name='brainpoolp160t1',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP192R1 = NamedGroupParams(
        name='brainpoolp192r1',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP192T1 = NamedGroupParams(
        name='brainpoolp192t1',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP224R1 = NamedGroupParams(
        name='brainpoolp224r1',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP224T1 = NamedGroupParams(
        name='brainpoolp224t1',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP256R1 = NamedGroupParams(
        name='brainpoolp256r1',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP256T1 = NamedGroupParams(
        name='brainpoolp256t1',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP320R1 = NamedGroupParams(
        name='brainpoolp320r1',
        size=320,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP320T1 = NamedGroupParams(
        name='brainpoolp320t1',
        size=320,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP384R1 = NamedGroupParams(
        name='brainpoolp384r1',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP384T1 = NamedGroupParams(
        name='brainpoolp384t1',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP512R1 = NamedGroupParams(
        name='brainpoolp512r1',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP512T1 = NamedGroupParams(
        name='brainpoolp512t1',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )

    CURVE25519 = NamedGroupParams(
        name='curve25519',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    CURVE448 = NamedGroupParams(
        name='curve448',
        size=448,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )

    FFDHE2048 = NamedGroupParams(
        name='ffdhe2048',
        size=2048,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE3072 = NamedGroupParams(
        name='ffdhe3072',
        size=3072,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE4096 = NamedGroupParams(
        name='ffdhe4096',
        size=4096,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE6144 = NamedGroupParams(
        name='ffdhe6144',
        size=6144,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE8192 = NamedGroupParams(
        name='ffdhe8192',
        size=8192,
        group_type=NamedGroupType.DH_PARAM,
    )
