# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import enum
import attr

from cryptoparser.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from cryptoparser.common.base import Serializable
from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable
from cryptoparser.common.base import ThreeByteEnumParsable, ThreeByteEnumComposer
from cryptoparser.tls.version import (
    TlsProtocolVersionBase,
    TlsProtocolVersionDraft,
    TlsProtocolVersionFinal,
    TlsVersion
)


class TlsCipherSuiteExtension(enum.IntEnum):
    FALLBACK_SCSV = 0x5600
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff


class TlsCipherSuiteFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsCipherSuite

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s  # pylint: disable=too-many-instance-attributes
class CipherSuiteParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    key_exchange = attr.ib(validator=attr.validators.optional(attr.validators.in_(KeyExchange)))
    authentication = attr.ib(validator=attr.validators.optional(attr.validators.in_(Authentication)))
    bulk_cipher = attr.ib(validator=attr.validators.optional(attr.validators.in_(BlockCipher)))
    block_cipher_mode = attr.ib(validator=attr.validators.optional(attr.validators.in_(BlockCipherMode)))
    mac = attr.ib(validator=attr.validators.optional(attr.validators.in_(MAC)))
    authenticated_encryption = attr.ib(validator=attr.validators.instance_of(bool))
    min_version = attr.ib(init=False, validator=attr.validators.instance_of(TlsProtocolVersionBase))

    def __attrs_post_init__(self):
        self.min_version = (
            TlsProtocolVersionDraft(1)
            if (self.code & 0xff00) == 0x1300
            else TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )


class TlsCipherSuite(TwoByteEnumComposer):
    TLS_NULL_WITH_NULL_NULL = CipherSuiteParams(
        code=0x0000,
        key_exchange=None,
        authentication=Authentication.anon,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=None,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_NULL_MD5 = CipherSuiteParams(
        code=0x0001,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0x0002,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(
        code=0x0003,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_40,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_RC4_128_MD5 = CipherSuiteParams(
        code=0x0004,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x0005,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuiteParams(
        code=0x0006,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC2_40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_IDEA_CBC_SHA = CipherSuiteParams(
        code=0x0007,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.IDEA,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
        code=0x0008,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0009,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x000a,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
        code=0x000b,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x000c,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x000d,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
        code=0x000e,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x000f,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x0010,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
        code=0x0011,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0012,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x0013,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(
        code=0x0014,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0015,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x0016,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0017,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.RC4_40,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_RC4_128_MD5 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0018,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0019,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_DES_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x001a,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x001b,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_FORTEZZA_KEA_WITH_NULL_SHA = CipherSuiteParams(
        code=0x001c,
        key_exchange=KeyExchange.FORTEZZA_KEA,
        authentication=Authentication.FORTEZZA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = CipherSuiteParams(
        code=0x001d,
        key_exchange=KeyExchange.FORTEZZA_KEA,
        authentication=Authentication.FORTEZZA,
        bulk_cipher=BlockCipher.FORTEZZA,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x001e,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x001f,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x0020,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_IDEA_CBC_SHA = CipherSuiteParams(
        code=0x0021,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.IDEA,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_DES_CBC_MD5 = CipherSuiteParams(
        code=0x0022,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = CipherSuiteParams(
        code=0x0023,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_RC4_128_MD5 = CipherSuiteParams(
        code=0x0024,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_WITH_IDEA_CBC_MD5 = CipherSuiteParams(
        code=0x0025,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.IDEA,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = CipherSuiteParams(
        code=0x0026,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = CipherSuiteParams(
        code=0x0027,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC2_40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA = CipherSuiteParams(
        code=0x0028,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC4_40,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = CipherSuiteParams(
        code=0x0029,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.DES40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = CipherSuiteParams(
        code=0x002a,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC2_40,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = CipherSuiteParams(
        code=0x002b,
        key_exchange=KeyExchange.KRB5,
        authentication=Authentication.KRB5,
        bulk_cipher=BlockCipher.RC4_40,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_NULL_SHA = CipherSuiteParams(
        code=0x002c,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_NULL_SHA = CipherSuiteParams(
        code=0x002d,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_NULL_SHA = CipherSuiteParams(
        code=0x002e,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x002f,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0030,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0031,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0032,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0033,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_AES_128_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0034,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0035,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0036,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0037,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0038,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0039,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_AES_256_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x003a,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_NULL_SHA256 = CipherSuiteParams(
        code=0x003b,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x003c,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
        code=0x003d,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x003e,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x003f,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x0040,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
        code=0x0041,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
        code=0x0042,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
        code=0x0043,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
        code=0x0044,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(
        code=0x0045,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0046,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_ECDH_ECDSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0x0047,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x0048,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0049,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x004a,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x004b,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x004c,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 = CipherSuiteParams(
        code=0x0060,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_56,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = CipherSuiteParams(
        code=0x0061,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC2_56,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0062,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,

    )
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0x0063,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = CipherSuiteParams(
        code=0x0064,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_56,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = CipherSuiteParams(
        code=0x0065,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.RC4_56,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x0066,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x0067,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
        code=0x0068,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
        code=0x0069,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
        code=0x006a,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(
        code=0x006b,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x006c,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x006d,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_GOSTR341094_WITH_28147_CNT_IMIT = CipherSuiteParams(
        code=0x0080,
        key_exchange=KeyExchange.GOST_R3410_94,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=BlockCipher.GOST2814789,
        block_cipher_mode=None,
        mac=MAC.IMIT_GOST28147,
        authenticated_encryption=False,
    )
    TLS_GOSTR341001_WITH_28147_CNT_IMIT = CipherSuiteParams(
        code=0x0081,
        key_exchange=KeyExchange.GOST_R3410_01,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=BlockCipher.GOST2814789,
        block_cipher_mode=None,
        mac=MAC.IMIT_GOST28147,
        authenticated_encryption=False,
    )
    TLS_GOSTR341094_WITH_NULL_GOSTR3411 = CipherSuiteParams(
        code=0x0082,
        key_exchange=KeyExchange.GOST_R3410_94,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.GOST_R3411_94,
        authenticated_encryption=False,
    )
    TLS_GOSTR341001_WITH_NULL_GOSTR3411 = CipherSuiteParams(
        code=0x0083,
        key_exchange=KeyExchange.GOST_R3410_01,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.GOST_R3411_94,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
        code=0x0084,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
        code=0x0085,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
        code=0x0086,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
        code=0x0087,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(
        code=0x0088,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x0089,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x008a,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x008b,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x008c,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x008d,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x008e,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x008f,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0090,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0091,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0x0092,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0x0093,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0x0094,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0x0095,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
        code=0x0096,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_SEED_CBC_SHA = CipherSuiteParams(
        code=0x0097,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
        code=0x0098,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_SEED_CBC_SHA = CipherSuiteParams(
        code=0x0099,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = CipherSuiteParams(
        code=0x009a,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_SEED_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x009b,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.SEED,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x009c,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x009d,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x009e,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x009f,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00a0,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00a1,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00a2,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00a3,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00a4,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00a5,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x00a6,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x00a7,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00a8,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00a9,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00aa,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00ab,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x00ac,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x00ad,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00ae,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0x00af,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
        code=0x00b0,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
        code=0x00b1,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00b2,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0x00b3,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
        code=0x00b4,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
        code=0x00b5,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00b6,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0x00b7,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
        code=0x00b8,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
        code=0x00b9,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00ba,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00bb,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00bc,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00bd,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0x00be,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x00bf,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
        code=0x00c0,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
        code=0x00c1,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
        code=0x00c2,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
        code=0x00c3,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(
        code=0x00c4,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0x00c5,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0x16b7,
        key_exchange=KeyExchange.CECPQ1,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0x16b8,
        key_exchange=KeyExchange.CECPQ1,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x16b9,
        key_exchange=KeyExchange.CECPQ1,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x16ba,
        key_exchange=KeyExchange.CECPQ1,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0xc001,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0xc002,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc003,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc004,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc005,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0xc006,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0xc007,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc008,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc009,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc00a,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0xc00b,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0xc00c,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc00d,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc00e,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc00f,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_NULL_SHA = CipherSuiteParams(
        code=0xc010,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0xc011,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc012,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc013,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc014,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_anon_WITH_NULL_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc015,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.anon,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_anon_WITH_RC4_128_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc016,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc017,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc018,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc019,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc01a,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.SRP,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc01b,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc01c,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc01d,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.SRP,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc01e,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc01f,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc020,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.SRP,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc021,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc022,
        key_exchange=KeyExchange.SRP,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc023,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc024,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc025,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc026,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc027,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc028,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc029,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc02a,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc02b,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc02c,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc02d,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc02e,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc02f,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc030,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc031,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc032,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_RC4_128_SHA = CipherSuiteParams(
        code=0xc033,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xc034,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = CipherSuiteParams(
        code=0xc035,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = CipherSuiteParams(
        code=0xc036,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc037,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc038,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA = CipherSuiteParams(
        code=0xc039,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA256 = CipherSuiteParams(
        code=0xc03a,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_NULL_SHA384 = CipherSuiteParams(
        code=0xc03b,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc03c,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc03d,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc03e,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc03f,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc040,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc041,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc042,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc043,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc044,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc045,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc046,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc047,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc048,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc049,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc04a,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc04b,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc04c,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc04d,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc04e,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc04f,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc050,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc051,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc052,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc053,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc054,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc055,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc056,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc057,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc058,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc059,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc05a,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc05b,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc05c,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc05d,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc05e,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc05f,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc060,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc061,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc062,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc063,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc064,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc065,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc066,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc067,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc068,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc069,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc06a,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc06b,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc06c,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc06d,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc06e,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc06f,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc070,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc071,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ARIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc072,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc073,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc074,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc075,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc076,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc077,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc078,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc079,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc07a,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc07b,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc07c,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc07d,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc07e,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc07f,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc080,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc081,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc082,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc083,
        key_exchange=KeyExchange.DH,
        authentication=Authentication.DSS,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc084,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(  # pylint: disable=invalid-name
        code=0xc085,
        key_exchange=KeyExchange.ADH,
        authentication=Authentication.anon,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc086,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc087,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc088,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc089,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc08a,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc08b,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc08c,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc08d,
        key_exchange=KeyExchange.ECDH,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc08e,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc08f,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc090,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc091,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = CipherSuiteParams(
        code=0xc092,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = CipherSuiteParams(
        code=0xc093,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc094,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc095,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc096,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc097,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc098,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc099,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = CipherSuiteParams(
        code=0xc09a,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = CipherSuiteParams(
        code=0xc09b,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CAMELLIA_256,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA2_384,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_AES_128_CCM = CipherSuiteParams(
        code=0xc09c,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_AES_256_CCM = CipherSuiteParams(
        code=0xc09d,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_128_CCM = CipherSuiteParams(
        code=0xc09e,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_256_CCM = CipherSuiteParams(
        code=0xc09f,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
        code=0xc0a0,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
        code=0xc0a1,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
        code=0xc0a2,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
        code=0xc0a3,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_128_CCM = CipherSuiteParams(
        code=0xc0a4,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_256_CCM = CipherSuiteParams(
        code=0xc0a5,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_AES_128_CCM = CipherSuiteParams(
        code=0xc0a6,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_AES_256_CCM = CipherSuiteParams(
        code=0xc0a7,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_128_CCM_8 = CipherSuiteParams(
        code=0xc0a8,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_AES_256_CCM_8 = CipherSuiteParams(
        code=0xc0a9,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_DHE_WITH_AES_128_CCM_8 = CipherSuiteParams(
        code=0xc0aa,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_PSK_DHE_WITH_AES_256_CCM_8 = CipherSuiteParams(
        code=0xc0ab,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = CipherSuiteParams(
        code=0xc0ac,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = CipherSuiteParams(
        code=0xc0ad,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = CipherSuiteParams(
        code=0xc0ae,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = CipherSuiteParams(
        code=0xc0af,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC = CipherSuiteParams(
        code=0xc100,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_128,
        block_cipher_mode=BlockCipherMode.EAX,
        mac=MAC.GOST_R3412_15_KUZNYECHIK_CTR_OMAC,
        authenticated_encryption=False,
    )
    TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC = CipherSuiteParams(
        code=0xc101,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_64,
        block_cipher_mode=BlockCipherMode.EAX,
        mac=MAC.GOST_R3412_15_MAGMA_CTR_OMAC,
        authenticated_encryption=False,
    )
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = CipherSuiteParams(
        code=0xc102,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST2814789,
        block_cipher_mode=BlockCipherMode.CNT,
        mac=MAC.IMIT_GOST28147,
        authenticated_encryption=False,
    )
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = CipherSuiteParams(
        code=0xc103,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_128,
        block_cipher_mode=BlockCipherMode.MGM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = CipherSuiteParams(
        code=0xc104,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_64,
        block_cipher_mode=BlockCipherMode.MGM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = CipherSuiteParams(
        code=0xc105,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_128,
        block_cipher_mode=BlockCipherMode.MGM,
        mac=None,
        authenticated_encryption=True,
    )
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = CipherSuiteParams(
        code=0xc106,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_12_256,
        bulk_cipher=BlockCipher.GOST_R3412_15_64,
        block_cipher_mode=BlockCipherMode.MGM,
        mac=None,
        authenticated_encryption=True,
    )
    OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xcc13,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xcc14,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xcc15,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xcca8,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xcca9,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xccaa,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xccab,
        key_exchange=KeyExchange.PSK,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xccac,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xccad,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0xccae,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0xd001,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0xd002,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = CipherSuiteParams(
        code=0xd003,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = CipherSuiteParams(
        code=0xd005,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=False,
    )
    TLS_AES_128_GCM_SHA256 = CipherSuiteParams(
        code=0x1301,
        key_exchange=None,
        authentication=None,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_AES_256_GCM_SHA384 = CipherSuiteParams(
        code=0x1302,
        key_exchange=None,
        authentication=None,
        bulk_cipher=BlockCipher.AES_256,
        block_cipher_mode=BlockCipherMode.GCM,
        mac=MAC.SHA2_384,
        authenticated_encryption=True,
    )
    TLS_CHACHA20_POLY1305_SHA256 = CipherSuiteParams(
        code=0x1303,
        key_exchange=None,
        authentication=None,
        bulk_cipher=BlockCipher.CHACHA20,
        block_cipher_mode=None,
        mac=MAC.POLY1305,
        authenticated_encryption=True,
    )
    TLS_AES_128_CCM_SHA256 = CipherSuiteParams(
        code=0x1304,
        key_exchange=None,
        authentication=None,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_AES_128_CCM_8_SHA256 = CipherSuiteParams(
        code=0x1305,
        key_exchange=None,
        authentication=None,
        bulk_cipher=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CCM_8,
        mac=MAC.SHA2_256,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe410,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_RSA_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe411,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe412,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_RSA_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe413,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe414,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe415,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.ECDSA,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe416,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_PSK_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe417,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe418,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_ECDHE_PSK_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe419,
        key_exchange=KeyExchange.ECDHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41a,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_RSA_PSK_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41b,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41c,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_DHE_PSK_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41d,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.PSK,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41e,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.ESTREAM_SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_DHE_RSA_WITH_SALSA20_SHA1 = CipherSuiteParams(
        code=0xe41f,
        key_exchange=KeyExchange.DHE,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.SALSA20,
        block_cipher_mode=None,
        mac=MAC.SHA1,
        authenticated_encryption=True,
    )
    TLS_RSA_FIPS_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0xfefe,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xfeff,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_RC2_CBC_MD5 = CipherSuiteParams(
        code=0xff80,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC2,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_IDEA_CBC_MD5 = CipherSuiteParams(
        code=0xff81,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.IDEA,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_DES_CBC_MD5 = CipherSuiteParams(
        code=0xff82,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    TLS_RSA_WITH_3DES_EDE_CBC_MD5 = CipherSuiteParams(
        code=0xff83,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    OLD_TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = CipherSuiteParams(
        code=0xff85,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=BlockCipher.GOST2814789,
        block_cipher_mode=None,
        mac=MAC.IMIT_GOST28147,
        authenticated_encryption=False,
    )
    TLS_GOSTR341112_256_WITH_NULL_GOSTR3411 = CipherSuiteParams(
        code=0xff87,
        key_exchange=KeyExchange.GOST_R3411_12_256,
        authentication=Authentication.GOST_R3410_94,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.GOST_R3411_94,
        authenticated_encryption=False,
    )
    OLD_TLS_RSA_FIPS_WITH_DES_CBC_SHA = CipherSuiteParams(
        code=0xffe0,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )
    OLD_TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = CipherSuiteParams(
        code=0xffe1,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False,
    )


class SslCipherKindFactory(ThreeByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SslCipherKind

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class SslCipherKind(Serializable, ThreeByteEnumComposer):
    SSL_CK_NULL_WITH_MD5 = CipherSuiteParams(
        code=0x000000,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False
    )
    SSL_CK_RC4_128_WITH_MD5 = CipherSuiteParams(
        code=0x010080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_RC4_128_EXPORT40_WITH_MD5 = CipherSuiteParams(
        code=0x020080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_RC2_128_CBC_WITH_MD5 = CipherSuiteParams(
        code=0x030080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC2_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = CipherSuiteParams(
        code=0x040080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC2_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_IDEA_128_CBC_WITH_MD5 = CipherSuiteParams(
        code=0x050080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.IDEA_128,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_DES_64_CBC_WITH_MD5 = CipherSuiteParams(
        code=0x060040,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_DES_64_CBC_WITH_SHA = CipherSuiteParams(
        code=0x060140,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False
    )
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = CipherSuiteParams(
        code=0x0700C0,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES_EDE,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.MD5,
        authenticated_encryption=False,
    )
    SSL_CK_DES_192_EDE3_CBC_WITH_SHA = CipherSuiteParams(
        code=0x0701C0,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.TRIPLE_DES,
        block_cipher_mode=BlockCipherMode.CBC,
        mac=MAC.SHA1,
        authenticated_encryption=False
    )
    SSL_CK_RC4_64_WITH_MD5 = CipherSuiteParams(
        code=0x080080,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.RC4_64,
        block_cipher_mode=None,
        mac=MAC.MD5,
        authenticated_encryption=False
    )
    SSL_CK_DES_64_CFB64_WITH_MD5_1 = CipherSuiteParams(
        code=0xFF8000,
        key_exchange=KeyExchange.RSA,
        authentication=Authentication.RSA,
        bulk_cipher=BlockCipher.DES,
        block_cipher_mode=BlockCipherMode.CFB,
        mac=MAC.MD5,
        authenticated_encryption=False
    )
    SSL_CK_NULL = CipherSuiteParams(
        code=0xFF8010,
        key_exchange=None,
        authentication=None,
        bulk_cipher=None,
        block_cipher_mode=None,
        mac=None,
        authenticated_encryption=False
    )
