# -*- coding: utf-8 -*-

import enum
import attr


@attr.s(frozen=True)
class KeyExchangeParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))
    forward_secret = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s(frozen=True)
class AuthenticationParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))
    anonymous = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s(frozen=True)
class BlockCipherParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))
    key_size = attr.ib(validator=attr.validators.instance_of(int))
    block_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s(frozen=True)
class BlockCipherModeParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))


@attr.s(frozen=True)
class MACParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))
    digest_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s(frozen=True)
class NamedGroupParams(object):
    name = attr.ib(validator=attr.validators.instance_of(str))
    size = attr.ib(validator=attr.validators.instance_of(int))
    group_type = attr.ib()


class KeyExchange(enum.Enum):
    ADH = KeyExchangeParams(
        name='ADH',
        forward_secret=False
    )
    CECPQ1 = KeyExchangeParams(
        name='CECPQ1',
        forward_secret=False
    )
    DH = KeyExchangeParams(  # pylint: disable=invalid-name
        name='DH',
        forward_secret=False
    )
    DHE = KeyExchangeParams(
        name='DHE',
        forward_secret=True
    )
    ECDH = KeyExchangeParams(
        name='ECDH',
        forward_secret=False
    )
    ECDHE = KeyExchangeParams(
        name='ECDHE',
        forward_secret=True
    )
    FORTEZZA_KEA = KeyExchangeParams(
        name='FORTEZZA_KEA',
        forward_secret=False
    )
    GOST_R3410_94 = KeyExchangeParams(
        name='GOST_R3410_94',
        forward_secret=True
    )
    GOST_R3410_01 = KeyExchangeParams(
        name='GOST_R3410_01',
        forward_secret=True
    )
    GOST_R3411_12_256 = KeyExchangeParams(
        name='GOST_R3411_12',
        forward_secret=True
    )
    KRB5 = KeyExchangeParams(
        name='KRB5',
        forward_secret=False
    )
    PSK = KeyExchangeParams(
        name='PSK',
        forward_secret=False
    )
    RSA = KeyExchangeParams(
        name='RSA',
        forward_secret=False
    )
    SRP = KeyExchangeParams(
        name='SRP',
        forward_secret=False
    )


class Authentication(enum.Enum):
    anon = AuthenticationParams(
        name='anon',
        anonymous=True,
    )
    DSS = AuthenticationParams(
        name='DSS',
        anonymous=False,
    )
    ECDSA = AuthenticationParams(
        name='ECDSA',
        anonymous=False,
    )
    FORTEZZA = AuthenticationParams(
        name='FORTEZZA',
        anonymous=False,
    )
    GOST_R3410_01 = AuthenticationParams(
        name='GOST_R3410_01',
        anonymous=False,
    )
    GOST_R3410_12_256 = AuthenticationParams(
        name='GOST_R3410_12_256',
        anonymous=False,
    )
    GOST_R3410_12_512 = AuthenticationParams(
        name='GOST_R3410_12_512',
        anonymous=False,
    )
    GOST_R3410_94 = AuthenticationParams(
        name='GOST_R3410_94',
        anonymous=False,
    )
    KRB5 = AuthenticationParams(
        name='KRB5',
        anonymous=False,
    )
    PSK = AuthenticationParams(
        name='PSK',
        anonymous=False,
    )
    RSA = AuthenticationParams(
        name='RSA',
        anonymous=False,
    )
    SRP = AuthenticationParams(
        name='SRP',
        anonymous=False,
    )
    EDDSA = AuthenticationParams(
        name='EdDSA',
        anonymous=False,
    )


class BlockCipher(enum.Enum):
    AES_128 = BlockCipherParams(
        name='AES_128',
        key_size=128,
        block_size=128,
    )
    AES_192 = BlockCipherParams(
        name='AES_192',
        key_size=192,
        block_size=128,
    )
    AES_256 = BlockCipherParams(
        name='AES_256',
        key_size=256,
        block_size=128,
    )
    ARIA_128 = BlockCipherParams(
        name='ARIA_128',
        key_size=128,
        block_size=128,
    )
    ARIA_192 = BlockCipherParams(
        name='ARIA_192',
        key_size=192,
        block_size=128,
    )
    ARIA_256 = BlockCipherParams(
        name='ARIA_256',
        key_size=256,
        block_size=128,
    )
    CAMELLIA_128 = BlockCipherParams(
        name='CAMELLIA_128',
        key_size=128,
        block_size=128,
    )
    CAMELLIA_256 = BlockCipherParams(
        name='CAMELLIA_256',
        key_size=256,
        block_size=128,
    )
    CHACHA20 = BlockCipherParams(
        name='CHACHA20',
        key_size=128,  # min
        #  key_size_max=256,
        block_size=None,
    )
    DES = BlockCipherParams(
        name='DES',
        key_size=56,
        block_size=64,
    )
    DES40 = BlockCipherParams(
        name='DES40',
        key_size=40,
        block_size=64,
    )
    ESTREAM_SALSA20 = BlockCipherParams(
        name='eSTREAM Salsa20',
        key_size=256,
        block_size=None,
    )
    FORTEZZA = BlockCipherParams(
        name='FORTEZZA',
        key_size=96,
        block_size=64,
    )
    GOST2814789 = BlockCipherParams(
        name='GOST2814789',
        key_size=64,
        block_size=256,
    )
    GOST_R3412_15_128 = BlockCipherParams(  # "Kuznyechik"
        name='GOST_R3412_15_128',
        key_size=256,
        block_size=128,
    )
    GOST_R3412_15_64 = BlockCipherParams(  # "Magma"
        name='GOST_R3412_15_64',
        key_size=256,
        block_size=64,
    )
    IDEA = BlockCipherParams(
        name='IDEA',
        key_size=64,
        block_size=64,
    )
    IDEA_128 = BlockCipherParams(
        name='IDEA_128',
        key_size=128,
        block_size=64,
    )
    RC2_40 = BlockCipherParams(
        name='RC2_40',
        key_size=40,
        block_size=64,
    )
    RC2 = BlockCipherParams(
        name='RC2',
        key_size=64,
        block_size=64,
    )
    RC2_56 = BlockCipherParams(
        name='RC2_56',
        key_size=56,
        block_size=64,
    )
    RC2_128 = BlockCipherParams(
        name='RC2_128',
        key_size=128,
        block_size=64,
    )
    RC4_40 = BlockCipherParams(
        name='RC4_40',
        key_size=40,
        block_size=None,
    )
    RC4_56 = BlockCipherParams(
        name='RC4_56',
        key_size=56,
        block_size=None,
    )
    RC4_64 = BlockCipherParams(
        name='RC4_64',
        key_size=64,
        block_size=None,
    )
    RC4_128 = BlockCipherParams(
        name='RC4_128',
        key_size=128,
        block_size=None,
    )
    SALSA20 = BlockCipherParams(
        name='Salsa20',
        key_size=256,
        block_size=None,
    )
    SEED = BlockCipherParams(
        name='SEED',
        key_size=128,
        block_size=128,
    )
    TRIPLE_DES = BlockCipherParams(
        name='3DES',
        key_size=128,  # min
        #  key_size_max=192,
        block_size=64,
    )
    TRIPLE_DES_EDE = BlockCipherParams(
        name='3DES_EDE',
        key_size=128,  # min
        #  key_size_max=192,
        block_size=64,
    )


class BlockCipherMode(enum.Enum):
    CBC = BlockCipherModeParams(
        name='CBC',
    )
    CCM = BlockCipherModeParams(
        name='CCM',
    )
    CCM_8 = BlockCipherModeParams(
        name='CCM_8',
    )
    CFB = BlockCipherModeParams(
        name='CFB',
    )
    CNT = BlockCipherModeParams(
        name='CNT',
    )
    CTR = BlockCipherModeParams(
        name='CTR',
    )
    GCM = BlockCipherModeParams(
        name='GCM',
    )
    MGM = BlockCipherModeParams(
        name='MGM',
    )


class MAC(enum.Enum):
    IMIT_GOST28147 = MACParams(
        name='IMIT_GOST28147',
        digest_size=256
    )
    GOST_R3411_94 = MACParams(
        name='GOST_R3411_94',
        digest_size=256
    )
    GOST_R3411_12_256 = MACParams(  # Streebog
        name='GOST_R3411_12_256',
        digest_size=256
    )
    GOST_R3411_12_512 = MACParams(  # Streebog
        name='GOST_R3411_12_512',
        digest_size=512
    )
    GOST_R3413_15 = MACParams(
        name='GOST_R3413_15',
        digest_size=None
    )
    MD5 = MACParams(
        name='MD5',
        digest_size=64
    )
    POLY1305 = MACParams(
        name='POLY1305',
        digest_size=128
    )
    SHA1 = MACParams(
        name='SHA1',
        digest_size=160
    )
    SHA224 = MACParams(
        name='SHA224',
        digest_size=224
    )
    SHA256 = MACParams(
        name='SHA256',
        digest_size=256
    )
    SHA384 = MACParams(
        name='SHA384',
        digest_size=384
    )
    SHA512 = MACParams(
        name='SHA512',
        digest_size=512
    )
    ED25519PH = MACParams(
        name='Ed25519ph',
        digest_size=255
    )
    ED448PH = MACParams(
        name='Ed448ph',
        digest_size=448
    )


class NamedGroupType(enum.IntEnum):
    ELLIPTIC_CURVE = 1
    DH_PARAM = 2


class NamedGroup(enum.Enum):
    GC256A = NamedGroupParams(
        name='tc26-gost-3410-2012-256-paramSetA',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256B = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-A-ParamSet',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256C = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-B-ParamSet',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256D = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-C-ParamSet',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512A = NamedGroupParams(
        name='tc26-gost-3410-12-512-paramSetA',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512B = NamedGroupParams(
        name='tc26-gost-3410-12-512-paramSetB',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512C = NamedGroupParams(
        name='tc26-gost-3410-2012-512-paramSetC',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
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
