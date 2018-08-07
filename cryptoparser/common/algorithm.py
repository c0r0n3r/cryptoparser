#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum
import collections

from cryptoparser.common.base import JSONSerializable

KeyExchangeParams = collections.namedtuple('KeyExchangeParams', ['name', 'pfs', ])
AuthenticationParams = collections.namedtuple('AuthenticationParams', ['name', 'anonymous', 'exportable', ])
BlockCipherParams = collections.namedtuple('BlockCipherParams', ['size', 'exportable', ])
BlockCipherModeParams = collections.namedtuple('BlockCipherModeParams', ['aead', ])
MACParams = collections.namedtuple('MACParams', ['size', ])
CipherSuiteParams = collections.namedtuple('TlsCipherSuiteParams', ['key_exchange', ])


class KeyExchange(enum.Enum):
    DH = KeyExchangeParams(
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
        key_size=128,
        block_size=128,
        exportable=True,
    )
    AES_192 = BlockCipherParams(
        key_size=192,
        block_size=128,
        exportable=True,
    )
    AES_256 = BlockCipherParams(
        key_size=256,
        block_size=128,
        exportable=True,
    )
    ARIA_128 = BlockCipherParams(
        key_size=128,
        block_size=128,
        exportable=True,
    )
    ARIA_192 = BlockCipherParams(
        key_size=192,
        block_size=128,
        exportable=True,
    )
    ARIA_256 = BlockCipherParams(
        key_size=256,
        block_size=128,
        exportable=True,
    )
    CAMELLIA_128 = BlockCipherParams(
        key_size=128,
        block_size=128,
        exportable=True,
    )
    CAMELLIA_256 = BlockCipherParams(
        key_size=256,
        block_size=128,
        exportable=True,
    )
    CHACHA20 = BlockCipherParams(
        key_size=64, # min
        # key_size_max=128,
        block_size=None,
        exportable=True,
    )
    DES = BlockCipherParams(
        key_size=56,
        block_size=64,
        exportable=True,
    )
    DES40 = BlockCipherParams(
        key_size=40,
        block_size=64,
        exportable=True,
    )
    IDEA = BlockCipherParams(
        key_size=64,
        block_size=64,
        exportable=True,
    )
    IDEA_128 = BlockCipherParams(
        key_size=128,
        block_size=64,
        exportable=True,
    )
    RC2_40 = BlockCipherParams(
        key_size=40,
        block_size=64,
        exportable=True,
    )
    RC2_128 = BlockCipherParams(
        key_size=128,
        block_size=64,
        exportable=True,
    )
    RC2_128_EXPORT40 = BlockCipherParams(
        key_size=40,
        block_size=64,
        exportable=True,
    )
    RC4_40 = BlockCipherParams(
        key_size=40,
        block_size=None,
        exportable=True,
    )
    RC4_128 = BlockCipherParams(
        key_size=128,
        block_size=None,
        exportable=True,
    )
    RC4_128_EXPORT40 = BlockCipherParams(
        key_size=40,
        block_size=None,
        exportable=True,
    )
    SEED = BlockCipherParams(
        key_size=128,
        block_size=128,
        exportable=True,
    )
    TRIPLE_DES = BlockCipherParams(
        key_size=128, # min
        # key_size_max=192,
        block_size=64,
        exportable=True,
    )
    TRIPLE_DES_EDE = BlockCipherParams(
        key_size=128, # min
        # key_size_max=192,
        block_size=64,
        exportable=True,
    )


class BlockCipherMode(enum.Enum):
    CBC = BlockCipherModeParams(
        aead=False
    )
    CCM = BlockCipherModeParams(
        aead=True
    )
    CCM_8 = BlockCipherModeParams(
        aead=True
    )
    GCM = BlockCipherModeParams(
        aead=True
    )
    POLY1305 = BlockCipherModeParams(
        aead=False
    )

    def __init__(self, params):
        self.params = params


class MAC(enum.Enum):
    MD5 = MACParams(
        size=64
    )
    SHA = MACParams(
        size=160
    )
    SHA224 = MACParams(
        size=224
    )
    SHA256 = MACParams(
        size=256
    )
    SHA384 = MACParams(
        size=384
    )
    SHA512 = MACParams(
        size=512
    )

    def __init__(self, params):
        self.params = params
