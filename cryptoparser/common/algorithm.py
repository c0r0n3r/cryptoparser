#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import collections

KeyExchangeParams = collections.namedtuple('KeyExchangeParams', ['name', 'pfs', ])
AuthenticationParams = collections.namedtuple('AuthenticationParams', ['name', 'anonymous', ])
BlockCipherParams = collections.namedtuple('BlockCipherParams', ['name', 'key_size', 'block_size', ])
BlockCipherModeParams = collections.namedtuple('BlockCipherModeParams', ['name', 'aead', ])
MACParams = collections.namedtuple('MACParams', ['name', 'digest_size', ])
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
    PSK = KeyExchangeParams(
        name='PSK',
        pfs=False
    )
    RSA = KeyExchangeParams(
        name='RSA',
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
    )
    DSS = AuthenticationParams(
        name='DSS',
        anonymous=False,
    )
    ECDSA = AuthenticationParams(
        name='ECDSA',
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
    RC4_128 = BlockCipherParams(
        name='RC4_128',
        key_size=128,
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
        digest_size=64
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
