# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import enum
import attr

from cryptoparser.common.base import Serializable
from cryptoparser.common.exception import InvalidValue


class AlgortihmOIDBase(object):
    @classmethod
    def from_oid(cls, oid):
        found_item = None

        for item in cls:
            if item.value.oid == oid:
                if found_item is not None:
                    raise InvalidValue(oid, cls, 'oid')

                found_item = item

        if found_item is None:
            raise InvalidValue(oid, cls, 'oid')

        return found_item


@attr.s(frozen=True)
class AlgortihmParams(Serializable):
    name = attr.ib(validator=attr.validators.instance_of(str))

    def _as_markdown(self, level):
        return self._markdown_result(self.name, level)


@attr.s(frozen=True)
class AlgortihmOIDOptionalParams(AlgortihmParams):
    oid = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))


@attr.s(frozen=True)
class AlgortihmOIDParams(AlgortihmParams):
    oid = attr.ib(validator=attr.validators.instance_of(str))


@attr.s(frozen=True)
class KeyExchangeParams(AlgortihmParams):
    forward_secret = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s(frozen=True)
class AuthenticationParams(AlgortihmOIDOptionalParams):
    anonymous = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s(frozen=True)
class BlockCipherParams(AlgortihmParams):
    key_size = attr.ib(validator=attr.validators.instance_of(int))
    block_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s(frozen=True)
class BlockCipherModeParams(AlgortihmParams):
    pass


@attr.s(frozen=True)
class NamedGroupParams(AlgortihmOIDOptionalParams):
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


class Authentication(AlgortihmOIDBase, enum.Enum):
    anon = AuthenticationParams(
        name='anon',
        oid=None,
        anonymous=True,
    )
    DSS = AuthenticationParams(
        name='DSS',
        oid='1.2.840.10040.4.1',
        anonymous=False,
    )
    ECDSA = AuthenticationParams(
        name='ECDSA',
        oid='1.2.840.10045.2.1',
        anonymous=False,
    )
    FORTEZZA = AuthenticationParams(
        name='FORTEZZA',
        oid=None,
        anonymous=False,
    )
    GOST2814789 = AuthenticationParams(
        name='GOST_R3410_89',
        oid='1.2.643.2.2.21',
        anonymous=False,
    )
    GOST_R3410_01 = AuthenticationParams(
        name='GOST_R3410_01',
        oid='1.2.643.2.2.19',
        anonymous=False,
    )
    GOST_R3410_12_256 = AuthenticationParams(
        name='GOST_R3410_12_256',
        oid='1.2.643.7.1.1.1.1',
        anonymous=False,
    )
    GOST_R3410_12_512 = AuthenticationParams(
        name='GOST_R3410_12_512',
        oid='1.2.643.7.1.1.1.2',
        anonymous=False,
    )
    GOST_R3410_94 = AuthenticationParams(
        name='GOST_R3410_94',
        oid='1.2.643.2.2.20',
        anonymous=False,
    )
    KRB5 = AuthenticationParams(
        name='KRB5',
        oid=None,
        anonymous=False,
    )
    PSK = AuthenticationParams(
        name='PSK',
        oid=None,
        anonymous=False,
    )
    RSA = AuthenticationParams(
        name='RSA',
        oid='1.2.840.113549.1.1.1',
        anonymous=False,
    )
    SRP = AuthenticationParams(
        name='SRP',
        oid=None,
        anonymous=False,
    )
    EDDSA = AuthenticationParams(
        name='EdDSA',
        oid=None,
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
    EAX = BlockCipherModeParams(
        name='EAX',
    )
    GCM = BlockCipherModeParams(
        name='GCM',
    )
    MGM = BlockCipherModeParams(
        name='MGM',
    )


@attr.s(frozen=True)
class HashParams(AlgortihmOIDParams):
    digest_size = attr.ib(attr.validators.instance_of(int))


class Hash(AlgortihmOIDBase, enum.Enum):
    GOST_R3411_94 = HashParams(
        name='GOST_R3411_94',
        oid='1.2.643.2.2.9',
        digest_size=256
    )
    GOST_R3411_12_256 = HashParams(  # Streebog
        name='GOST_R3411_12_256',
        oid='1.0.10118.3.0.56',
        digest_size=256
    )
    GOST_R3411_12_512 = HashParams(  # Streebog
        name='GOST_R3411_12_512',
        oid='1.0.10118.3.0.56',
        digest_size=512
    )
    MD2 = HashParams(
        name='MD2',
        oid='1.2.840.113549.2.2',
        digest_size=128
    )
    MD4 = HashParams(
        name='MD4',
        oid='1.2.840.113549.2.4',
        digest_size=128
    )
    MD5 = HashParams(
        name='MD5',
        oid='1.2.840.113549.2.5',
        digest_size=64
    )
    SHA1 = HashParams(
        name='SHA1',
        oid='1.3.14.3.2.18',
        digest_size=160
    )
    SHA2_224 = HashParams(
        name='SHA2_224',
        oid='2.16.840.1.101.3.4.2.4',
        digest_size=224
    )
    SHA2_256 = HashParams(
        name='SHA2_256',
        oid='2.16.840.1.101.3.4.2.1',
        digest_size=256
    )
    SHA2_384 = HashParams(
        name='SHA2_384',
        oid='2.16.840.1.101.3.4.2.2',
        digest_size=384
    )
    SHA2_512 = HashParams(
        name='SHA2_512',
        oid='2.16.840.1.101.3.4.2.3',
        digest_size=512
    )
    SHA2_512_224 = HashParams(
        name='SHA2_512_224',
        oid='2.16.840.1.101.3.4.2.5',
        digest_size=224
    )
    SHA2_512_256 = HashParams(
        name='SHA2_512_256',
        oid='2.16.840.1.101.3.4.2.6',
        digest_size=256
    )
    SHA3_224 = HashParams(
        name='SHA3_224',
        oid='2.16.840.1.101.3.4.2.7',
        digest_size=224
    )
    SHA3_256 = HashParams(
        name='SHA3_256',
        oid='2.16.840.1.101.3.4.2.8',
        digest_size=256
    )
    SHA3_384 = HashParams(
        name='SHA3_384',
        oid='2.16.840.1.101.3.4.2.9',
        digest_size=384
    )
    SHA3_512 = HashParams(
        name='SHA3_512',
        oid='2.16.840.1.101.3.4.2.10',
        digest_size=512
    )
    SHAKE_128 = HashParams(
        name='SHAKE_128',
        oid='2.16.840.1.101.3.4.2.11',
        digest_size=128
    )
    SHAKE_256 = HashParams(
        name='SHAKE_256',
        oid='2.16.840.1.101.3.4.2.12',
        digest_size=256
    )
    ED25519PH = HashParams(
        name='Ed25519ph',
        oid='1.3.101.114',
        digest_size=255
    )
    ED448PH = HashParams(
        name='Ed448ph',
        oid='1.3.101.115',
        digest_size=448
    )


@attr.s(frozen=True)
class MACParamsBase(AlgortihmOIDOptionalParams):
    pass


@attr.s(frozen=True)
class MACParams(MACParamsBase):
    digest_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s(frozen=True)
class HMACParams(MACParamsBase):
    hash_algo = attr.ib(attr.validators.in_(Hash))

    @property
    def digest_size(self):
        return self.hash_algo.value.digest_size


class MAC(AlgortihmOIDBase, enum.Enum):
    IMIT_GOST28147 = MACParams(
        name='IMIT_GOST28147',
        oid='1.2.643.2.2.22',
        digest_size=None
    )
    GOST_R3411_94 = HMACParams(
        name='GOST_R3411_94',
        oid='1.2.643.2.2.10',
        hash_algo=Hash.GOST_R3411_94
    )
    GOST_R3411_12_256 = HMACParams(  # Streebog
        name='GOST_R3411_12_256',
        oid='1.2.643.7.1.1.4.1',
        hash_algo=Hash.GOST_R3411_12_256
    )
    GOST_R3411_12_512 = HMACParams(  # Streebog
        name='GOST_R3411_12_512',
        oid='1.2.643.7.1.1.4.2',
        hash_algo=Hash.GOST_R3411_12_512
    )
    GOST_R3412_15_KUZNYECHIK_CTR_OMAC = MACParams(  # Kuznyechik
        name='GOST_R3412_15_KUZNYECHIK_CTR_OMAC',
        oid='1.2.643.7.1.1.5.1.2',
        digest_size=None
    )
    GOST_R3412_15_MAGMA_CTR_OMAC = MACParams(  # Kuznyechik
        name='GOST_R3412_15_MAGMA_CTR_OMAC',
        oid='1.2.643.7.1.1.5.2.2',
        digest_size=None
    )
    MD5 = HMACParams(
        name='MD5',
        oid='1.2.840.113549.2.6',
        hash_algo=Hash.MD5
    )
    POLY1305 = MACParams(
        name='POLY1305',
        oid=None,
        digest_size=128
    )
    SHA1 = HMACParams(
        name='SHA1',
        oid='1.2.840.113549.2.7',
        hash_algo=Hash.SHA1
    )
    SHA2_224 = HMACParams(
        name='SHA2_224',
        oid='1.2.840.113549.2.8',
        hash_algo=Hash.SHA2_224
    )
    SHA2_256 = HMACParams(
        name='SHA2_256',
        oid='1.2.840.113549.2.9',
        hash_algo=Hash.SHA2_256
    )
    SHA2_384 = HMACParams(
        name='SHA2_384',
        oid='1.2.840.113549.2.10',
        hash_algo=Hash.SHA2_384
    )
    SHA2_512 = HMACParams(
        name='SHA2_512',
        oid='1.2.840.113549.2.11',
        hash_algo=Hash.SHA2_512
    )
    SHA2_512_224 = HMACParams(
        name='SHA2_512_224',
        oid='1.2.840.113549.2.12',
        hash_algo=Hash.SHA2_512_224
    )
    SHA2_512_256 = HMACParams(
        name='SHA2_512_256',
        oid='1.2.840.113549.2.13',
        hash_algo=Hash.SHA2_512_256
    )
    SHA3_224 = HMACParams(
        name='SHA3_224',
        oid='2.16.840.1.101.3.4.2.13',
        hash_algo=Hash.SHA3_224
    )
    SHA3_256 = HMACParams(
        name='SHA3_256',
        oid='2.16.840.1.101.3.4.2.14',
        hash_algo=Hash.SHA3_256
    )
    SHA3_384 = HMACParams(
        name='SHA3_384',
        oid='2.16.840.1.101.3.4.2.15',
        hash_algo=Hash.SHA3_384
    )
    SHA3_512 = HMACParams(
        name='SHA3_512',
        oid='2.16.840.1.101.3.4.2.16',
        hash_algo=Hash.SHA3_512
    )
    ED25519PH = HMACParams(
        name='Ed25519ph',
        oid='1.3.101.114',
        hash_algo=Hash.ED25519PH
    )
    ED448PH = HMACParams(
        name='Ed448ph',
        oid='1.3.101.115',
        hash_algo=Hash.ED448PH
    )


class NamedGroupType(enum.IntEnum):
    ELLIPTIC_CURVE = 1
    DH_PARAM = 2


class NamedGroup(AlgortihmOIDBase, enum.Enum):
    C2PNB163V1 = NamedGroupParams(
        name='c2pnb163v1',
        oid='1.2.840.10045.3.0.1',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB163V2 = NamedGroupParams(
        name='c2pnb163v2',
        oid='1.2.840.10045.3.0.2',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB163V3 = NamedGroupParams(
        name='c2pnb163v3',
        oid='1.2.840.10045.3.0.3',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB176W1 = NamedGroupParams(
        name='c2pnb176w1',
        oid='1.2.840.10045.3.0.4',
        size=176,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB191V1 = NamedGroupParams(
        name='c2tnb191v1',
        oid='1.2.840.10045.3.0.5',
        size=191,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB191V2 = NamedGroupParams(
        name='c2tnb191v2',
        oid='1.2.840.10045.3.0.6',
        size=191,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB191V3 = NamedGroupParams(
        name='c2tnb191v3',
        oid='1.2.840.10045.3.0.7',
        size=191,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2ONB191V4 = NamedGroupParams(
        name='c2onb191v4',
        oid='1.2.840.10045.3.0.8',
        size=191,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2ONB191V5 = NamedGroupParams(
        name='c2onb191v5',
        oid='1.2.840.10045.3.0.9',
        size=191,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB208W1 = NamedGroupParams(
        name='c2pnb208w1',
        oid='1.2.840.10045.3.0.10',
        size=208,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB239V1 = NamedGroupParams(
        name='c2tnb239v1',
        oid='1.2.840.10045.3.0.11',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB239V2 = NamedGroupParams(
        name='c2tnb239v2',
        oid='1.2.840.10045.3.0.12',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB239V3 = NamedGroupParams(
        name='c2tnb239v3',
        oid='1.2.840.10045.3.0.13',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2ONB239V4 = NamedGroupParams(
        name='c2onb239v4',
        oid='1.2.840.10045.3.0.14',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2ONB239V5 = NamedGroupParams(
        name='c2onb239v5',
        oid='1.2.840.10045.3.0.15',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB272W1 = NamedGroupParams(
        name='c2pnb272w1',
        oid='1.2.840.10045.3.0.16',
        size=272,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB304W1 = NamedGroupParams(
        name='c2pnb304w1',
        oid='1.2.840.10045.3.0.17',
        size=304,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB359V1 = NamedGroupParams(
        name='c2tnb359v1',
        oid='1.2.840.10045.3.0.18',
        size=359,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2PNB368W1 = NamedGroupParams(
        name='c2pnb368w1',
        oid='1.2.840.10045.3.0.19',
        size=368,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    C2TNB431R1 = NamedGroupParams(
        name='c2tnb431r1',
        oid='1.2.840.10045.3.0.20',
        size=431,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256A = NamedGroupParams(
        name='tc26-gost-3410-2012-256-paramSetA',
        oid='1.2.643.7.1.2.1.1.1',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256B = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-A-ParamSet',
        size=256,
        oid='1.2.643.2.2.35.1',
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256C = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-B-ParamSet',
        oid='1.2.643.2.2.35.2',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC256D = NamedGroupParams(
        name='GostR3410-2001-CryptoPro-C-ParamSet',
        oid='1.2.643.2.2.35.3',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512A = NamedGroupParams(
        name='tc26-gost-3410-12-512-paramSetA',
        oid='1.2.643.7.1.2.1.2.1',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512B = NamedGroupParams(
        name='tc26-gost-3410-12-512-paramSetB',
        oid='1.2.643.7.1.2.1.2.2',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    GC512C = NamedGroupParams(
        name='tc26-gost-3410-2012-512-paramSetC',
        oid='1.2.643.7.1.2.1.2.3',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME239V1 = NamedGroupParams(
        name='prime239v1',
        oid='1.2.840.10045.3.1.4',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME239V2 = NamedGroupParams(
        name='prime239v2',
        oid='1.2.840.10045.3.1.5',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME239V3 = NamedGroupParams(
        name='prime239v3',
        oid='1.2.840.10045.3.1.6',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP112R1 = NamedGroupParams(
        name='secp112r1',
        oid='1.3.132.0.6',
        size=112,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP112R2 = NamedGroupParams(
        name='secp112r2',
        oid='1.3.132.0.7',
        size=112,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP128R1 = NamedGroupParams(
        name='secp128r1',
        oid='1.3.132.0.28',
        size=128,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP128R2 = NamedGroupParams(
        name='secp128r2',
        oid='1.3.132.0.29',
        size=128,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT113R1 = NamedGroupParams(
        name='sect113r1',
        oid='1.3.132.0.4',
        size=113,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT113R2 = NamedGroupParams(
        name='sect113r2',
        oid='1.3.132.0.5',
        size=113,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT131R1 = NamedGroupParams(
        name='sect131r1',
        oid='1.3.132.0.22',
        size=131,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT131R2 = NamedGroupParams(
        name='sect131r2',
        oid='1.3.132.0.23',
        size=131,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT163K1 = NamedGroupParams(
        name='sect163k1',
        oid='1.3.132.0.1',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT163R1 = NamedGroupParams(
        name='sect163r1',
        oid='1.3.132.0.2',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT163R2 = NamedGroupParams(
        name='sect163r2',
        oid='1.3.132.0.15',
        size=163,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT193R1 = NamedGroupParams(
        name='sect193r1',
        oid='1.3.132.0.24',
        size=193,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT193R2 = NamedGroupParams(
        name='sect193r2',
        oid='1.3.132.0.25',
        size=193,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT233K1 = NamedGroupParams(
        name='sect233k1',
        oid='1.3.132.0.26',
        size=233,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT233R1 = NamedGroupParams(
        name='sect233r1',
        oid='1.3.132.0.27',
        size=233,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT239K1 = NamedGroupParams(
        name='sect239k1',
        oid='1.3.132.0.3',
        size=239,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT283K1 = NamedGroupParams(
        name='sect283k1',
        oid='1.3.132.0.16',
        size=283,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT283R1 = NamedGroupParams(
        name='sect283r1',
        oid='1.3.132.0.17',
        size=283,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT409K1 = NamedGroupParams(
        name='sect409k1',
        oid='1.3.132.0.36',
        size=409,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT409R1 = NamedGroupParams(
        name='sect409r1',
        oid='1.3.132.0.37',
        size=409,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT571K1 = NamedGroupParams(
        name='sect571k1',
        oid='1.3.132.0.38',
        size=571,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECT571R1 = NamedGroupParams(
        name='sect571r1',
        oid='1.3.132.0.39',
        size=571,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160K1 = NamedGroupParams(
        name='secp160k1',
        oid='1.3.132.0.9',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160R1 = NamedGroupParams(
        name='secp160r1',
        oid='1.3.132.0.8',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP160R2 = NamedGroupParams(
        name='secp160r2',
        oid='1.3.132.0.30',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP192K1 = NamedGroupParams(
        name='secp192k1',
        oid='1.3.132.0.31',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME192V1 = NamedGroupParams(
        name='prime192v1',
        oid='1.2.840.10045.3.1.1',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME192V2 = NamedGroupParams(
        name='prime192v2',
        oid='1.2.840.10045.3.1.2',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME192V3 = NamedGroupParams(
        name='prime192v3',
        oid='1.2.840.10045.3.1.3',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP224K1 = NamedGroupParams(
        name='secp224k1',
        oid='1.3.132.0.32',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP224R1 = NamedGroupParams(
        name='secp224r1',
        oid='1.3.132.0.33',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP256K1 = NamedGroupParams(
        name='secp256k1',
        oid='1.3.132.0.10',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    PRIME256V1 = NamedGroupParams(
        name='prime256v1',
        oid='1.2.840.10045.3.1.7',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP384R1 = NamedGroupParams(
        name='secp384r1',
        oid='1.3.132.0.34',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    SECP521R1 = NamedGroupParams(
        name='secp521r1',
        oid='1.3.132.0.35',
        size=521,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )

    BRAINPOOLP160R1 = NamedGroupParams(
        name='brainpoolp160r1',
        oid='1.3.36.3.3.2.8.1.1.1',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP160T1 = NamedGroupParams(
        name='brainpoolp160t1',
        oid='1.3.36.3.3.2.8.1.1.2',
        size=160,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP192R1 = NamedGroupParams(
        name='brainpoolp192r1',
        oid='1.3.36.3.3.2.8.1.1.3',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP192T1 = NamedGroupParams(
        name='brainpoolp192t1',
        oid='1.3.36.3.3.2.8.1.1.4',
        size=192,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP224R1 = NamedGroupParams(
        name='brainpoolp224r1',
        oid='1.3.36.3.3.2.8.1.1.5',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP224T1 = NamedGroupParams(
        name='brainpoolp224t1',
        oid='1.3.36.3.3.2.8.1.1.6',
        size=224,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP256R1 = NamedGroupParams(
        name='brainpoolp256r1',
        oid='1.3.36.3.3.2.8.1.1.7',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP256T1 = NamedGroupParams(
        name='brainpoolp256t1',
        oid='1.3.36.3.3.2.8.1.1.8',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP320R1 = NamedGroupParams(
        name='brainpoolp320r1',
        oid='1.3.36.3.3.2.8.1.1.9',
        size=320,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP320T1 = NamedGroupParams(
        name='brainpoolp320t1',
        oid='1.3.36.3.3.2.8.1.1.10',
        size=320,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP384R1 = NamedGroupParams(
        name='brainpoolp384r1',
        oid='1.3.36.3.3.2.8.1.1.11',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP384T1 = NamedGroupParams(
        name='brainpoolp384t1',
        oid='1.3.36.3.3.2.8.1.1.12',
        size=384,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP512R1 = NamedGroupParams(
        name='brainpoolp512r1',
        oid='1.3.36.3.3.2.8.1.1.13',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    BRAINPOOLP512T1 = NamedGroupParams(
        name='brainpoolp512t1',
        oid='1.3.36.3.3.2.8.1.1.14',
        size=512,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    CURVE25519 = NamedGroupParams(
        name='curve25519',
        oid='1.3.101.110',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    CURVE448 = NamedGroupParams(
        name='curve448',
        oid='1.3.101.111',
        size=448,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )

    FFDHE2048 = NamedGroupParams(
        name='ffdhe2048',
        oid=None,
        size=2048,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE3072 = NamedGroupParams(
        name='ffdhe3072',
        oid=None,
        size=3072,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE4096 = NamedGroupParams(
        name='ffdhe4096',
        oid=None,
        size=4096,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE6144 = NamedGroupParams(
        name='ffdhe6144',
        oid=None,
        size=6144,
        group_type=NamedGroupType.DH_PARAM,
    )
    FFDHE8192 = NamedGroupParams(
        name='ffdhe8192',
        oid=None,
        size=8192,
        group_type=NamedGroupType.DH_PARAM,
    )


@attr.s(frozen=True)
class SignatureParams(AlgortihmOIDParams):
    name = attr.ib(validator=attr.validators.instance_of(str))
    oid = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))
    key_type = attr.ib(validator=attr.validators.in_(Authentication))
    hash_algorithm = attr.ib(validator=attr.validators.in_(Hash))


class Signature(AlgortihmOIDBase, enum.Enum):
    RSA_WITH_MD2 = SignatureParams(
        name='md2WithRSAEncryption',
        oid='1.2.840.113549.1.1.2',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD2
    )
    RSA_WITH_MD4 = SignatureParams(
        name='md4WithRSAEncryption',
        oid='1.2.840.113549.1.1.3',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD4
    )
    RSA_WITH_MD5 = SignatureParams(
        name='md5WithRSAEncryption',
        oid='1.2.840.113549.1.1.4',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD5
    )
    RSA_WITH_SHA1 = SignatureParams(
        name='sha1-with-rsa-signature',
        oid='1.2.840.113549.1.1.5',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA1
    )
    RSA_WITH_SHA2_224 = SignatureParams(
        name='sha224WithRSAEncryption',
        oid='1.2.840.113549.1.1.14',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_224
    )
    RSA_WITH_SHA2_256 = SignatureParams(
        name='sha256WithRSAEncryption',
        oid='1.2.840.113549.1.1.11',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_WITH_SHA2_384 = SignatureParams(
        name='sha384WithRSAEncryption',
        oid='1.2.840.113549.1.1.12',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_WITH_SHA2_512 = SignatureParams(
        name='sha512WithRSAEncryption',
        oid='1.2.840.113549.1.1.13',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )
    DSA_WITH_SHA1 = SignatureParams(
        name='dsa_sha1',
        oid='1.2.840.10040.4.3',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA1
    )
    DSA_WITH_SHA2_224 = SignatureParams(
        name='dsa_sha224',
        oid='2.16.840.1.101.3.4.3.1',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA2_224
    )
    DSA_WITH_SHA2_256 = SignatureParams(
        name='dsa_sha256',
        oid='2.16.840.1.101.3.4.3.2',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_WITH_SHA1 = SignatureParams(
        name='ecdsa_sha1',
        oid='1.2.840.10045.4.1',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA1
    )
    ECDSA_WITH_SHA2_224 = SignatureParams(
        name='ecdsa_sha224',
        oid='1.2.840.10045.4.3.1',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_224
    )
    ECDSA_WITH_SHA2_256 = SignatureParams(
        name='ecdsa_sha256',
        oid='1.2.840.10045.4.3.2',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_WITH_SHA2_384 = SignatureParams(
        name='ecdsa_sha384',
        oid='1.2.840.10045.4.3.3',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_384
    )
    ECDSA_WITH_SHA2_512 = SignatureParams(
        name='ecdsa_sha512',
        oid='1.2.840.10045.4.3.4',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_512
    )
    ECDSA_WITH_SHA3_224 = SignatureParams(
        name='ecdsa_sha224',
        oid='2.16.840.1.101.3.4.3.9',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_224
    )
    ECDSA_WITH_SHA3_256 = SignatureParams(
        name='ecdsa_sha256',
        oid='2.16.840.1.101.3.4.3.10',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_256
    )
    ECDSA_WITH_SHA3_384 = SignatureParams(
        name='ecdsa_sha384',
        oid='2.16.840.1.101.3.4.3.11',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_384
    )
    ECDSA_WITH_SHA3_512 = SignatureParams(
        name='ecdsa_sha512',
        oid='2.16.840.1.101.3.4.3.12',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_512
    )
    GOST_R3410_01 = SignatureParams(
        name='gost_r3410_01',
        oid='1.2.643.2.2.3',
        key_type=Authentication.GOST_R3410_01,
        hash_algorithm=Hash.GOST_R3411_94,
    )
    GOST_R3410_12_256_R3410 = SignatureParams(
        name='id-tc26-signwithdigest-gost3410-12-94',
        oid='1.2.643.7.1.1.3.1',
        key_type=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3411_12_256_R3410 = SignatureParams(
        name='id-tc26-signwithdigest-gost3410-12-256',
        oid='1.2.643.7.1.1.3.2',
        key_type=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3410_12_512 = SignatureParams(
        name='id-tc26-signwithdigest-gost3410-12-512',
        oid='1.2.643.7.1.1.3.3',
        key_type=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )
