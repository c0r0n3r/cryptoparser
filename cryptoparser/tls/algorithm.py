# -*- coding: utf-8 -*-

import abc

import attr

from cryptoparser.common.algorithm import Authentication, Hash, NamedGroup
from cryptoparser.common.base import (
    OneByteEnumComposer,
    OneByteEnumParsable,
    OpaqueEnumComposer,
    TwoByteEnumComposer,
    TwoByteEnumParsable
)


class TlsNamedCurveFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsNamedCurve

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(frozen=True)
class TlsNamedCurveParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    named_group = attr.ib(validator=attr.validators.optional(attr.validators.in_(NamedGroup)))


class TlsNamedCurve(TwoByteEnumComposer):
    SECT163K1 = TlsNamedCurveParams(
        code=0x0001,
        named_group=NamedGroup.SECT163K1,
    )
    SECT163R1 = TlsNamedCurveParams(
        code=0x0002,
        named_group=NamedGroup.SECT163R1,
    )
    SECT163R2 = TlsNamedCurveParams(
        code=0x0003,
        named_group=NamedGroup.SECT163R2,
    )
    SECT193R1 = TlsNamedCurveParams(
        code=0x0004,
        named_group=NamedGroup.SECT193R1,
    )
    SECT193R2 = TlsNamedCurveParams(
        code=0x0005,
        named_group=NamedGroup.SECT193R2,
    )
    SECT233K1 = TlsNamedCurveParams(
        code=0x0006,
        named_group=NamedGroup.SECT233K1,
    )
    SECT233R1 = TlsNamedCurveParams(
        code=0x0007,
        named_group=NamedGroup.SECT233R1,
    )
    SECT239K1 = TlsNamedCurveParams(
        code=0x0008,
        named_group=NamedGroup.SECT239K1,
    )
    SECT283K1 = TlsNamedCurveParams(
        code=0x0009,
        named_group=NamedGroup.SECT283K1,
    )
    SECT283R1 = TlsNamedCurveParams(
        code=0x000a,
        named_group=NamedGroup.SECT283R1,
    )
    SECT409K1 = TlsNamedCurveParams(
        code=0x000b,
        named_group=NamedGroup.SECT409K1,
    )
    SECT409R1 = TlsNamedCurveParams(
        code=0x000c,
        named_group=NamedGroup.SECT409R1,
    )
    SECT571K1 = TlsNamedCurveParams(
        code=0x000d,
        named_group=NamedGroup.SECT571K1,
    )
    SECT571R1 = TlsNamedCurveParams(
        code=0x000e,
        named_group=NamedGroup.SECT571R1,
    )
    SECP160K1 = TlsNamedCurveParams(
        code=0x000f,
        named_group=NamedGroup.SECP160K1,
    )
    SECP160R1 = TlsNamedCurveParams(
        code=0x0010,
        named_group=NamedGroup.SECP160R1,
    )
    SECP160R2 = TlsNamedCurveParams(
        code=0x0011,
        named_group=NamedGroup.SECP160R2,
    )
    SECP192K1 = TlsNamedCurveParams(
        code=0x0012,
        named_group=NamedGroup.SECP192K1,
    )
    SECP192R1 = TlsNamedCurveParams(
        code=0x0013,
        named_group=NamedGroup.PRIME192V1,
    )
    SECP224K1 = TlsNamedCurveParams(
        code=0x0014,
        named_group=NamedGroup.SECP224K1,
    )
    SECP224R1 = TlsNamedCurveParams(
        code=0x0015,
        named_group=NamedGroup.SECP224R1,
    )
    SECP256K1 = TlsNamedCurveParams(
        code=0x0016,
        named_group=NamedGroup.SECP256K1,
    )
    SECP256R1 = TlsNamedCurveParams(
        code=0x0017,
        named_group=NamedGroup.PRIME256V1,
    )
    SECP384R1 = TlsNamedCurveParams(
        code=0x0018,
        named_group=NamedGroup.SECP384R1,
    )
    SECP521R1 = TlsNamedCurveParams(
        code=0x0019,
        named_group=NamedGroup.SECP521R1,
    )
    GC256A = TlsNamedCurveParams(
        code=0x0022,
        named_group=NamedGroup.GC256A,
    )
    GC256B = TlsNamedCurveParams(
        code=0x0023,
        named_group=NamedGroup.GC256B,
    )
    GC256C = TlsNamedCurveParams(
        code=0x0024,
        named_group=NamedGroup.GC256C,
    )
    GC256D = TlsNamedCurveParams(
        code=0x0025,
        named_group=NamedGroup.GC256D,
    )
    GC512A = TlsNamedCurveParams(
        code=0x0026,
        named_group=NamedGroup.GC512A,
    )
    GC512B = TlsNamedCurveParams(
        code=0x0027,
        named_group=NamedGroup.GC512B,
    )
    GC512C = TlsNamedCurveParams(
        code=0x0028,
        named_group=NamedGroup.GC512C,
    )

    BRAINPOOLP256R1 = TlsNamedCurveParams(
        code=0x001a,
        named_group=NamedGroup.BRAINPOOLP256R1,
    )
    BRAINPOOLP384R1 = TlsNamedCurveParams(
        code=0x001b,
        named_group=NamedGroup.BRAINPOOLP384R1,
    )
    BRAINPOOLP512R1 = TlsNamedCurveParams(
        code=0x001c,
        named_group=NamedGroup.BRAINPOOLP512R1,
    )
    X25519 = TlsNamedCurveParams(
        code=0x001d,
        named_group=NamedGroup.CURVE25519,
    )
    X448 = TlsNamedCurveParams(
        code=0x001e,
        named_group=NamedGroup.CURVE448,
    )

    FFDHE2048 = TlsNamedCurveParams(
        code=0x0100,
        named_group=NamedGroup.FFDHE2048,
    )
    FFDHE3072 = TlsNamedCurveParams(
        code=0x0101,
        named_group=NamedGroup.FFDHE3072,
    )
    FFDHE4096 = TlsNamedCurveParams(
        code=0x0102,
        named_group=NamedGroup.FFDHE4096,
    )
    FFDHE6144 = TlsNamedCurveParams(
        code=0x0103,
        named_group=NamedGroup.FFDHE6144,
    )
    FFDHE8192 = TlsNamedCurveParams(
        code=0x0104,
        named_group=NamedGroup.FFDHE8192,
    )

    ARBITRARY_EXPLICIT_PRIME_CURVES = TlsNamedCurveParams(
        code=0xff01,
        named_group=None,
    )
    ARBITRARY_EXPLICIT_CHAR2_CURVES = TlsNamedCurveParams(
        code=0xff02,
        named_group=None,
    )


class TlsSignatureAndHashAlgorithmFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsSignatureAndHashAlgorithm

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(frozen=True)
class HashAndSignatureAlgorithmParam(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    hash_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.in_(Hash)))
    signature_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.in_(Authentication)))


class TlsSignatureAndHashAlgorithm(TwoByteEnumComposer):
    ANONYMOUS_NONE = HashAndSignatureAlgorithmParam(
        code=0x0000,
        signature_algorithm=Authentication.anon,
        hash_algorithm=None,
    )
    ANONYMOUS_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0100,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.MD5
    )
    ANONYMOUS_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0200,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA1
    )
    ANONYMOUS_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0300,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_224
    )
    ANONYMOUS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0400,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_256
    )
    ANONYMOUS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0500,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_384
    )
    ANONYMOUS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0006,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_512
    )
    RSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0001,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=None,
    )
    RSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0101,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.MD5
    )
    RSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0201,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA1
    )
    RSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0301,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_224
    )
    RSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0401,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0501,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0601,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )
    DSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0002,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=None,
    )
    DSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0102,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.MD5
    )
    DSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0202,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA1
    )
    DSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0302,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_224
    )
    DSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0402,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_256
    )
    DSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0502,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_384
    )
    DSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0602,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_512
    )
    ECDSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0003,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=None,
    )
    ECDSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0103,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.MD5
    )
    ECDSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0203,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA1
    )
    ECDSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0303,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_224
    )
    ECDSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0403,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0503,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_384
    )
    ECDSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0603,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_512
    )
    GOST_R3410_01 = HashAndSignatureAlgorithmParam(
        code=0x00ed,
        signature_algorithm=Authentication.GOST_R3410_01,
        hash_algorithm=Hash.GOST_R3411_94,
    )
    OLD_GOST_R3410_12_256 = HashAndSignatureAlgorithmParam(
        code=0x00ee,
        signature_algorithm=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    OLD_GOST_R3410_12_512 = HashAndSignatureAlgorithmParam(
        code=0x00ef,
        signature_algorithm=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )
    GOST_R3410_12_256 = HashAndSignatureAlgorithmParam(
        code=0x4008,
        signature_algorithm=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3410_12_512 = HashAndSignatureAlgorithmParam(
        code=0x4108,
        signature_algorithm=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )

    RSA_PSS_RSAE_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0804,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_PSS_RSAE_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0805,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_PSS_RSAE_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0806,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )

    ED25519 = HashAndSignatureAlgorithmParam(
        code=0x0807,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=Hash.ED25519PH
    )
    ED448 = HashAndSignatureAlgorithmParam(
        code=0x0808,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=Hash.ED448PH
    )

    RSA_PSS_PSS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0809,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_PSS_PSS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x080a,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_PSS_PSS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x080b,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )


class TlsECPointFormatFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsECPointFormat

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(frozen=True)
class TlsECPointFormatParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))


class TlsECPointFormat(OneByteEnumComposer):
    UNCOMPRESSED = TlsECPointFormatParams(code=0x00)
    ANSIX962_COMPRESSED_PRIME = TlsECPointFormatParams(code=0x01)
    ANSIX962_COMPRESSED_CHAR2 = TlsECPointFormatParams(code=0x02)


@attr.s(frozen=True)
class TlsProtocolNameParams(object):
    code = attr.ib(validator=attr.validators.instance_of(str))


class TlsProtocolName(OpaqueEnumComposer):
    C_WEBRTC = TlsProtocolNameParams(
        code='c-webrtc',
    )
    COAP = TlsProtocolNameParams(
        code='coap',
    )
    FTP = TlsProtocolNameParams(
        code='ftp',
    )
    H2 = TlsProtocolNameParams(
        code='h2',
    )
    H2_14 = TlsProtocolNameParams(
        code='h2-14',
    )
    H2_15 = TlsProtocolNameParams(
        code='h2-15',
    )
    H2_16 = TlsProtocolNameParams(
        code='h2-16',
    )
    H2C = TlsProtocolNameParams(
        code='h2c',
    )
    HTTP_0_9 = TlsProtocolNameParams(
        code='http/0.9',
    )
    HTTP_1_0 = TlsProtocolNameParams(
        code='http/1.0',
    )
    HTTP_1_1 = TlsProtocolNameParams(
        code='http/1.1',
    )
    IMAP = TlsProtocolNameParams(
        code='imap',
    )
    MANAGESIEVE = TlsProtocolNameParams(
        code='managesieve',
    )
    POP3 = TlsProtocolNameParams(
        code='pop3',
    )
    SPDY_1 = TlsProtocolNameParams(
        code='spdy/1',
    )
    SPDY_2 = TlsProtocolNameParams(
        code='spdy/2',
    )
    SPDY_3 = TlsProtocolNameParams(
        code='spdy/3',
    )
    SPDY_3_1 = TlsProtocolNameParams(
        code='spdy/3.1',
    )
    STUN_NAT_DISCOVERY = TlsProtocolNameParams(
        code='stun.nat-discovery',
    )
    STUN_TURN = TlsProtocolNameParams(
        code='stun.turn',
    )
    WEBRTC = TlsProtocolNameParams(
        code='webrtc',
    )
    XMPP_CLIENT = TlsProtocolNameParams(
        code='xmpp-client',
    )
    XMPP_SERVER = TlsProtocolNameParams(
        code='xmpp-server',
    )


class TlsNextProtocolName(OpaqueEnumComposer):
    HTTP_1_1 = TlsProtocolNameParams(
        code='http/1.1',
    )
    SPDY_1 = TlsProtocolNameParams(
        code='spdy/1',
    )
    SPDY_2 = TlsProtocolNameParams(
        code='spdy/2',
    )
    SPDY_3 = TlsProtocolNameParams(
        code='spdy/3',
    )
    SPDY_3_1 = TlsProtocolNameParams(
        code='spdy/3.1',
    )
    SPDY_4_A_2 = TlsProtocolNameParams(
        code='spdy/4a2',
    )
