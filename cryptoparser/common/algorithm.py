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
        name='Anonymous Diffie–Hellman (ADH)',
        forward_secret=False
    )
    CECPQ1 = KeyExchangeParams(
        name='Combined Elliptic-Curve and Post-Quantum 1 (CECPQ1)',
        forward_secret=False
    )
    DH = KeyExchangeParams(  # pylint: disable=invalid-name
        name='static Diffie–Hellman Ephemeral (DH)',
        forward_secret=False
    )
    DHE = KeyExchangeParams(
        name='Diffie–Hellman Ephemeral (DHE)',
        forward_secret=True
    )
    ECDH = KeyExchangeParams(
        name='static Elliptic-curve Diffie–Hellman (ECDH)',
        forward_secret=False
    )
    ECDHE = KeyExchangeParams(
        name='Elliptic-curve Diffie–Hellman Ephemeral (ECDHE)',
        forward_secret=True
    )
    FORTEZZA_KEA = KeyExchangeParams(
        name='Fortezza Key Exchange Algortihm (KEA)',
        forward_secret=False
    )
    GOST_R3410_94 = KeyExchangeParams(
        name='GOST R 34.10-94',
        forward_secret=True
    )
    GOST_R3410_01 = KeyExchangeParams(
        name='GOST R 34.10-2001',
        forward_secret=True
    )
    GOST_R3411_12_256 = KeyExchangeParams(
        name='GOST R 34.11-2012',
        forward_secret=True
    )
    KRB5 = KeyExchangeParams(
        name='Kerberos V5 (KRB5)',
        forward_secret=False
    )
    PSK = KeyExchangeParams(
        name='Pre-shared Key (PKS)',
        forward_secret=False
    )
    RSA = KeyExchangeParams(
        name='Rivest–Shamir–Adleman (RSA)',
        forward_secret=False
    )
    SNTRUP_X25519 = KeyExchangeParams(
        name='Streamlined NTRU Prime coupled with X25519',
        forward_secret=False
    )
    SRP = KeyExchangeParams(
        name='Secure Remote Password (SRP)',
        forward_secret=False
    )


class Authentication(AlgortihmOIDBase, enum.Enum):
    anon = AuthenticationParams(  # pylint: disable=invalid-name
        name='anon',
        oid=None,
        anonymous=True,
    )
    DSS = AuthenticationParams(
        name='Digital Signature Standard (DSS)',
        oid='1.2.840.10040.4.1',
        anonymous=False,
    )
    ECDSA = AuthenticationParams(
        name='Elliptic Curve Digital Signature Algorithm (ECDSA)',
        oid='1.2.840.10045.2.1',
        anonymous=False,
    )
    FORTEZZA = AuthenticationParams(
        name='Fortezza',
        oid=None,
        anonymous=False,
    )
    GOST2814789 = AuthenticationParams(
        name='GOST 28147-89',
        oid='1.2.643.2.2.21',
        anonymous=False,
    )
    GOST_R3410_01 = AuthenticationParams(
        name='GOST R 34.10-2001',
        oid='1.2.643.2.2.19',
        anonymous=False,
    )
    GOST_R3410_12_256 = AuthenticationParams(
        name='GOST R 34.10-2012 (256)',
        oid='1.2.643.7.1.1.1.1',
        anonymous=False,
    )
    GOST_R3410_12_512 = AuthenticationParams(
        name='GOST R 34.10-2012 (512)',
        oid='1.2.643.7.1.1.1.2',
        anonymous=False,
    )
    GOST_R3410_94 = AuthenticationParams(
        name='GOST R 34.10-94',
        oid='1.2.643.2.2.20',
        anonymous=False,
    )
    KRB5 = AuthenticationParams(
        name='Kerberos V5 (KRB5)',
        oid=None,
        anonymous=False,
    )
    PSK = AuthenticationParams(
        name='Pre-shared Key (PKS)',
        oid=None,
        anonymous=False,
    )
    RSA = AuthenticationParams(
        name='Rivest–Shamir–Adleman (RSA)',
        oid='1.2.840.113549.1.1.1',
        anonymous=False,
    )
    SRP = AuthenticationParams(
        name='Secure Remote Password (SRP)',
        oid=None,
        anonymous=False,
    )
    EDDSA = AuthenticationParams(
        name='Edwards-curve Digital Signature Algorithm (EdDSA)',
        oid=None,
        anonymous=False,
    )


class BlockCipher(enum.Enum):
    ACSS = BlockCipherParams(
        name='ACSS',
        key_size=40,
        block_size=None,
    )
    AES_128 = BlockCipherParams(
        name='AES-128',
        key_size=128,
        block_size=128,
    )
    AES_192 = BlockCipherParams(
        name='AES-192',
        key_size=192,
        block_size=128,
    )
    AES_256 = BlockCipherParams(
        name='AES-256',
        key_size=256,
        block_size=128,
    )
    ARIA_128 = BlockCipherParams(
        name='ARIA-128',
        key_size=128,
        block_size=128,
    )
    ARIA_192 = BlockCipherParams(
        name='ARIA-192',
        key_size=192,
        block_size=128,
    )
    ARIA_256 = BlockCipherParams(
        name='ARIA-256',
        key_size=256,
        block_size=128,
    )
    BLOWFISH = BlockCipherParams(
        name='Blowfish',
        key_size=32,  # min
        # key_size_max=448,
        block_size=64,
    )
    TWOFISH128 = BlockCipherParams(
        name='Twofish-128',
        key_size=128,
        block_size=128,
    )
    TWOFISH192 = BlockCipherParams(
        name='Twofish-192',
        key_size=192,
        block_size=192,
    )
    TWOFISH256 = BlockCipherParams(
        name='Twofish-256',
        key_size=256,
        block_size=256,
    )
    CAMELLIA_128 = BlockCipherParams(
        name='Camellia-128',
        key_size=128,
        block_size=128,
    )
    CAMELLIA_256 = BlockCipherParams(
        name='Camellia-256',
        key_size=256,
        block_size=128,
    )
    CAST_128 = BlockCipherParams(
        name='CAST-128',
        key_size=40,  # min
        # key_size_max=128,
        block_size=64,
    )
    CAST_256 = BlockCipherParams(
        name='CAST-256',
        key_size=128,  # min
        # key_size_max=256,
        block_size=128,
    )
    CHACHA20 = BlockCipherParams(
        name='ChaCha20',
        key_size=128,  # min
        # key_size_max=256,
        block_size=None,
    )
    CRYPTICORE = BlockCipherParams(  # Rabbit
        name='CryptiCore',
        key_size=128,
        block_size=None,
    )
    DES = BlockCipherParams(
        name='DES',
        key_size=56,
        block_size=64,
    )
    DES40 = BlockCipherParams(
        name='DES-40',
        key_size=40,
        block_size=64,
    )
    ESTREAM_SALSA20 = BlockCipherParams(
        name='eSTREAM Salsa20',
        key_size=256,
        block_size=None,
    )
    FORTEZZA = BlockCipherParams(
        name='Fortezza',
        key_size=96,
        block_size=64,
    )
    GOST2814789 = BlockCipherParams(
        name='GOST 28147-89',
        key_size=64,
        block_size=256,
    )
    GOST_R3412_15_128 = BlockCipherParams(  # "Kuznyechik"
        name='GOST R 34.12-2015 "Kuznyechik"',
        key_size=256,
        block_size=128,
    )
    GOST_R3412_15_64 = BlockCipherParams(  # "Magma"
        name='GOST R 34.12-2015 "Magma"',
        key_size=256,
        block_size=64,
    )
    IDEA = BlockCipherParams(
        name='IDEA',
        key_size=64,
        block_size=64,
    )
    IDEA_128 = BlockCipherParams(
        name='IDEA-128',
        key_size=128,
        block_size=64,
    )
    RC2_40 = BlockCipherParams(
        name='RC2-40',
        key_size=40,
        block_size=64,
    )
    RC2 = BlockCipherParams(
        name='RC2',
        key_size=64,
        block_size=64,
    )
    RC2_56 = BlockCipherParams(
        name='RC2-56',
        key_size=56,
        block_size=64,
    )
    RC2_128 = BlockCipherParams(
        name='RC2-128',
        key_size=128,
        block_size=64,
    )
    RC4_40 = BlockCipherParams(
        name='RC4-40',
        key_size=40,
        block_size=None,
    )
    RC4_56 = BlockCipherParams(
        name='RC4-56',
        key_size=56,
        block_size=None,
    )
    RC4_64 = BlockCipherParams(
        name='RC4-64',
        key_size=64,
        block_size=None,
    )
    RC4_128 = BlockCipherParams(
        name='RC4-128',
        key_size=128,
        block_size=None,
    )
    RC4_256 = BlockCipherParams(
        name='RC4-256',
        key_size=256,
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
    SERPENT_128 = BlockCipherParams(
        name='Serpent-128',
        key_size=128,
        block_size=128,
    )
    SERPENT_192 = BlockCipherParams(
        name='Serpent-192',
        key_size=192,
        block_size=128,
    )
    SERPENT_256 = BlockCipherParams(
        name='Serpent-256',
        key_size=256,
        block_size=128,
    )
    TRIPLE_DES = BlockCipherParams(
        name='Triple DES (TDEA)',
        key_size=128,  # min
        # key_size_max=192,
        block_size=64,
    )
    TRIPLE_DES_EDE = BlockCipherParams(
        name='Triple DES (TDEA) EDE',
        key_size=128,  # min
        # key_size_max=192,
        block_size=64,
    )


class BlockCipherMode(enum.Enum):
    CBC = BlockCipherModeParams(
        name='Cipher Block Chaining (CBC)',
    )
    CCM = BlockCipherModeParams(
        name='Counter with CBC-MAC (CCM)',
    )
    CCM_8 = BlockCipherModeParams(
        name='Counter with CBC-MAC (CCM-8)',
    )
    CFB = BlockCipherModeParams(
        name='Cipher Feedback (CFB)',
    )
    CNT = BlockCipherModeParams(
        name='GOST Counter (CNT)',
    )
    CTR = BlockCipherModeParams(
        name='Counter (CTR)',
    )
    ECB = BlockCipherModeParams(
        name='Electronic Codebook (ECB)',
    )
    EAX = BlockCipherModeParams(
        name='encrypt-then-authenticate-then-translate (EAX)',
    )
    GCM = BlockCipherModeParams(
        name='Galois/Counter Mode (GCM)',
    )
    MGM = BlockCipherModeParams(
        name='GOST Magma (MGM)',
    )
    OFB = BlockCipherModeParams(
        name='Output Feedback (OFB)',
    )


@attr.s(frozen=True)
class HashParams(AlgortihmOIDOptionalParams):
    digest_size = attr.ib(attr.validators.instance_of(int))


class Hash(AlgortihmOIDBase, enum.Enum):
    GOST_R3411_94 = HashParams(
        name='GOST R 34.11-94',
        oid='1.2.643.2.2.9',
        digest_size=256
    )
    GOST_R3411_12_256 = HashParams(  # Streebog
        name='GOST R 34.11-2012 "Streebog" (256)',
        oid='1.0.10118.3.0.56',
        digest_size=256
    )
    GOST_R3411_12_512 = HashParams(  # Streebog
        name='GOST R 34.11-2012 "Streebog" (512)',
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
    RIPEMD128 = HashParams(
        name='RIPEMD-128',
        oid='1.3.36.3.2.2',
        digest_size=128
    )
    RIPEMD160 = HashParams(
        name='RIPEMD-160',
        oid='1.3.36.3.2.1',
        digest_size=160
    )
    RIPEMD256 = HashParams(
        name='RIPEMD-256',
        oid='1.3.36.3.2.3',
        digest_size=256
    )
    SHA1 = HashParams(
        name='SHA-1',
        oid='1.3.14.3.2.18',
        digest_size=160
    )
    SHA2_224 = HashParams(
        name='SHA-224',
        oid='2.16.840.1.101.3.4.2.4',
        digest_size=224
    )
    SHA2_256 = HashParams(
        name='SHA-256',
        oid='2.16.840.1.101.3.4.2.1',
        digest_size=256
    )
    SHA2_384 = HashParams(
        name='SHA-384',
        oid='2.16.840.1.101.3.4.2.2',
        digest_size=384
    )
    SHA2_512 = HashParams(
        name='SHA-512',
        oid='2.16.840.1.101.3.4.2.3',
        digest_size=512
    )
    SHA2_512_224 = HashParams(
        name='SHA-512/224',
        oid='2.16.840.1.101.3.4.2.5',
        digest_size=224
    )
    SHA2_512_256 = HashParams(
        name='SHA-512/256',
        oid='2.16.840.1.101.3.4.2.6',
        digest_size=256
    )
    SHA3_224 = HashParams(
        name='SHA-224',
        oid='2.16.840.1.101.3.4.2.7',
        digest_size=224
    )
    SHA3_256 = HashParams(
        name='SHA-256',
        oid='2.16.840.1.101.3.4.2.8',
        digest_size=256
    )
    SHA3_384 = HashParams(
        name='SHA-384',
        oid='2.16.840.1.101.3.4.2.9',
        digest_size=384
    )
    SHA3_512 = HashParams(
        name='SHA-512',
        oid='2.16.840.1.101.3.4.2.10',
        digest_size=512
    )
    SHAKE_128 = HashParams(
        name='SHAKE128',
        oid='2.16.840.1.101.3.4.2.11',
        digest_size=128
    )
    SHAKE_256 = HashParams(
        name='SHAKE256',
        oid='2.16.840.1.101.3.4.2.12',
        digest_size=256
    )
    TIGER_128 = HashParams(
        name='Tiger/128',
        oid=None,
        digest_size=128
    )
    TIGER_128_96 = HashParams(
        name='Tiger/128(96)',
        oid=None,
        digest_size=96
    )
    TIGER_160 = HashParams(
        name='Tiger/160',
        oid=None,
        digest_size=160
    )
    TIGER_160_96 = HashParams(
        name='Tiger/160(96)',
        oid=None,
        digest_size=96
    )
    TIGER_192 = HashParams(
        name='Tiger/192',
        oid='1.3.6.1.4.1.11591.12.2',
        digest_size=192
    )
    TIGER_192_96 = HashParams(
        name='Tiger/192(96)',
        oid=None,
        digest_size=96
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
    WHIRLPOOL = HashParams(
        name='Whirlpool',
        oid='1.0.10118.3.0.55',
        digest_size=512
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
    AEAD_AES_128_CCM = MACParams(
        name='AEAD_AES_128_CCM',
        oid=None,
        digest_size=128
    )
    AEAD_AES_128_GCM = MACParams(
        name='AEAD_AES_128_GCM',
        oid=None,
        digest_size=128
    )
    AEAD_AES_256_CCM = MACParams(
        name='AEAD_AES_256_CCM',
        oid=None,
        digest_size=256
    )
    AEAD_AES_256_GCM = MACParams(
        name='AEAD_AES_256_GCM',
        oid=None,
        digest_size=256
    )
    CRYPTICORE = MACParams(
        name='CryptiCore',  # Badger
        oid=None,
        digest_size=128
    )
    IMIT_GOST28147 = MACParams(
        name='MAC GOST 28147-89',
        oid='1.2.643.2.2.22',
        digest_size=None
    )
    GOST_R3411_94 = HMACParams(
        name='HMAC GOST R 34.11-94',
        oid='1.2.643.2.2.10',
        hash_algo=Hash.GOST_R3411_94
    )
    GOST_R3411_12_256 = HMACParams(  # Streebog
        name='HMAC GOST R 34.11-2012 "Streebog" (256)',
        oid='1.2.643.7.1.1.4.1',
        hash_algo=Hash.GOST_R3411_12_256
    )
    GOST_R3411_12_512 = HMACParams(  # Streebog
        name='HMAC GOST R 34.11-2012 "Streebog" (512)',
        oid='1.2.643.7.1.1.4.2',
        hash_algo=Hash.GOST_R3411_12_512
    )
    GOST_R3412_15_KUZNYECHIK_CTR_OMAC = MACParams(  # Kuznyechik
        name='CTR OMAC GOST R 34.12-2015 "Kuznyechik"',
        oid='1.2.643.7.1.1.5.2.2',
        digest_size=None
    )
    GOST_R3412_15_MAGMA_CTR_OMAC = MACParams(  # Kuznyechik
        name='CTR OMAC GOST R 34.12-2015 "Magma"',
        oid='1.2.643.7.1.1.5.1.2',
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
    RIPEMD128 = HMACParams(
        name='RIPEMD-128',
        oid=None,
        hash_algo=Hash.RIPEMD128,
    )
    RIPEMD160 = HMACParams(
        name='RIPEMD-160',
        oid=None,
        hash_algo=Hash.RIPEMD160,
    )
    RIPEMD256 = HMACParams(
        name='RIPEMD-256',
        oid=None,
        hash_algo=Hash.RIPEMD256,
    )
    SHA1 = HMACParams(
        name='SHA-1',
        oid='1.2.840.113549.2.7',
        hash_algo=Hash.SHA1
    )
    SHA2_224 = HMACParams(
        name='SHA2-224',
        oid='1.2.840.113549.2.8',
        hash_algo=Hash.SHA2_224
    )
    SHA2_256 = HMACParams(
        name='SHA2-256',
        oid='1.2.840.113549.2.9',
        hash_algo=Hash.SHA2_256
    )
    SHA2_384 = HMACParams(
        name='SHA2-384',
        oid='1.2.840.113549.2.10',
        hash_algo=Hash.SHA2_384
    )
    SHA2_512 = HMACParams(
        name='SHA2-512',
        oid='1.2.840.113549.2.11',
        hash_algo=Hash.SHA2_512
    )
    SHA2_512_224 = HMACParams(
        name='SHA-512/224',
        oid='1.2.840.113549.2.12',
        hash_algo=Hash.SHA2_512_224
    )
    SHA2_512_256 = HMACParams(
        name='SHA-512/256',
        oid='1.2.840.113549.2.13',
        hash_algo=Hash.SHA2_512_256
    )
    SHA3_224 = HMACParams(
        name='SHA3-224',
        oid='2.16.840.1.101.3.4.2.13',
        hash_algo=Hash.SHA3_224
    )
    SHA3_256 = HMACParams(
        name='SHA3-256',
        oid='2.16.840.1.101.3.4.2.14',
        hash_algo=Hash.SHA3_256
    )
    SHA3_384 = HMACParams(
        name='SHA3-384',
        oid='2.16.840.1.101.3.4.2.15',
        hash_algo=Hash.SHA3_384
    )
    SHA3_512 = HMACParams(
        name='SHA3-512',
        oid='2.16.840.1.101.3.4.2.16',
        hash_algo=Hash.SHA3_512
    )
    TIGER_128 = HMACParams(
        name='Tiger/128',
        oid=None,
        hash_algo=Hash.TIGER_128
    )
    TIGER_128_96 = HMACParams(
        name='Tiger/128(96)',
        oid=None,
        hash_algo=Hash.TIGER_128_96
    )
    TIGER_160 = HMACParams(
        name='Tiger/160',
        oid=None,
        hash_algo=Hash.TIGER_160
    )
    TIGER_160_96 = HMACParams(
        name='Tiger/160(96)',
        oid=None,
        hash_algo=Hash.TIGER_160_96
    )
    TIGER_192 = HMACParams(
        name='Tiger/192',
        oid='1.3.6.1.5.5.8.1.3',
        hash_algo=Hash.TIGER_192
    )
    TIGER_192_96 = HMACParams(
        name='Tiger/192(96)',
        oid=None,
        hash_algo=Hash.TIGER_192_96
    )
    UMAC_32 = MACParams(
        name='UMAC-32',
        oid=None,
        digest_size=32
    )
    UMAC_64 = MACParams(
        name='UMAC-64',
        oid=None,
        digest_size=64
    )
    UMAC_96 = MACParams(
        name='UMAC-96',
        oid=None,
        digest_size=96
    )
    UMAC_128 = MACParams(
        name='UMAC-128',
        oid=None,
        digest_size=128
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
    WHIRLPOOL = HMACParams(
        name='Whirlpool',
        oid=None,
        hash_algo=Hash.WHIRLPOOL
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
        name='Curve25519',
        oid='1.3.101.110',
        size=256,
        group_type=NamedGroupType.ELLIPTIC_CURVE,
    )
    CURVE448 = NamedGroupParams(
        name='Curve448',
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
        name='MD2 with RSA Encryption',
        oid='1.2.840.113549.1.1.2',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD2
    )
    RSA_WITH_MD4 = SignatureParams(
        name='MD4 with RSA Encryption',
        oid='1.2.840.113549.1.1.3',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD4
    )
    RSA_WITH_MD5 = SignatureParams(
        name='MD5 with RSA Encryption',
        oid='1.2.840.113549.1.1.4',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.MD5
    )
    RSA_WITH_SHA1 = SignatureParams(
        name='SHA-1 with RSA Encryption',
        oid='1.2.840.113549.1.1.5',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA1
    )
    RSA_WITH_SHA2_224 = SignatureParams(
        name='SHA-224 with RSA Encryption',
        oid='1.2.840.113549.1.1.14',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_224
    )
    RSA_WITH_SHA2_256 = SignatureParams(
        name='SHA-256 with RSA Encryption',
        oid='1.2.840.113549.1.1.11',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_WITH_SHA2_384 = SignatureParams(
        name='SHA-384 with RSA Encryption',
        oid='1.2.840.113549.1.1.12',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_WITH_SHA2_512 = SignatureParams(
        name='SHA-512 with RSA Encryption',
        oid='1.2.840.113549.1.1.13',
        key_type=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )
    DSA_WITH_SHA1 = SignatureParams(
        name='DSA with SHA-1',
        oid='1.2.840.10040.4.3',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA1
    )
    DSA_WITH_SHA2_224 = SignatureParams(
        name='DSA with SHA-224',
        oid='2.16.840.1.101.3.4.3.1',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA2_224
    )
    DSA_WITH_SHA2_256 = SignatureParams(
        name='DSA with SHA-256',
        oid='2.16.840.1.101.3.4.3.2',
        key_type=Authentication.DSS,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_WITH_SHA1 = SignatureParams(
        name='ECDSA with SHA-1',
        oid='1.2.840.10045.4.1',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA1
    )
    ECDSA_WITH_SHA2_224 = SignatureParams(
        name='ECDSA with SHA-224',
        oid='1.2.840.10045.4.3.1',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_224
    )
    ECDSA_WITH_SHA2_256 = SignatureParams(
        name='ECDSA with SHA-256',
        oid='1.2.840.10045.4.3.2',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_WITH_SHA2_384 = SignatureParams(
        name='ECDSA with SHA-384',
        oid='1.2.840.10045.4.3.3',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_384
    )
    ECDSA_WITH_SHA2_512 = SignatureParams(
        name='ECDSA with SHA-512',
        oid='1.2.840.10045.4.3.4',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_512
    )
    ECDSA_WITH_SHA3_224 = SignatureParams(
        name='ECDSA with SHA3-224',
        oid='2.16.840.1.101.3.4.3.9',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_224
    )
    ECDSA_WITH_SHA3_256 = SignatureParams(
        name='ECDSA with SHA3-256',
        oid='2.16.840.1.101.3.4.3.10',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_256
    )
    ECDSA_WITH_SHA3_384 = SignatureParams(
        name='ECDSA with SHA3-384',
        oid='2.16.840.1.101.3.4.3.11',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_384
    )
    ECDSA_WITH_SHA3_512 = SignatureParams(
        name='ECDSA with SHA3-512',
        oid='2.16.840.1.101.3.4.3.12',
        key_type=Authentication.ECDSA,
        hash_algorithm=Hash.SHA3_512
    )
    GOST_R3410_01 = SignatureParams(
        name='GOST R 34.10-2001 with GOST R 34.11-94',
        oid='1.2.643.2.2.3',
        key_type=Authentication.GOST_R3410_01,
        hash_algorithm=Hash.GOST_R3411_94,
    )
    GOST_R3410_12_94_R3410 = SignatureParams(
        name='GOST R 34.10-2012 with GOST R 34.11-2012 (94)',
        oid='1.2.643.7.1.1.3.1',
        key_type=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3411_12_256_R3410 = SignatureParams(
        name='GOST R 34.10-2012 with GOST R 34.11-2012 (256)',
        oid='1.2.643.7.1.1.3.2',
        key_type=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3411_12_512_R3410 = SignatureParams(
        name='GOST R 34.10-2012 with GOST R 34.11-2012 (256)',
        oid='1.2.643.7.1.1.3.3',
        key_type=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )
