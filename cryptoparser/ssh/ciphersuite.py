
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import enum

from cryptoparser.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from cryptoparser.common.base import StringEnumParsable, StringEnum


class MACMode(enum.Enum):
    ENCRYPT_THEN_MAC = enum.auto()
    ENCRYPT_AND_MAC = enum.auto()
    MAC_THEN_ENCRYP = enum.auto()


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

KexAlgorithmParams = collections.namedtuple(
    'KexAlgorithmParams',
    [
        'code',
        'kex',
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


class SshEncryptionAlgorithms(StringEnum, enum.Enum):
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
    CAST128_CBC = EncryptionAlgorithmParams(
        code='cast128-cbc',
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
    RIJNDAEL_CBC_LYSATOR_LIU_SE = EncryptionAlgorithmParams(
        code='rijndael-cbc@lysator-liu-se',
        cipher=BlockCipher.AES_256,
        mode=BlockCipherMode.CBC,
    )
    TRIPLE_DES_CBC = EncryptionAlgorithmParams(
        code='3des-cbc',
        cipher=BlockCipher.TRIPLE_DES,
        mode=BlockCipherMode.CBC,
    )


class SshMacAlgorithms(StringEnum, enum.Enum):
    HMAC_SHA1 = MACParams(
        code='hmac-sha1',
        size=MAC.SHA1.value.size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1_96 = MACParams(
        code='hmac-sha1-96',
        size=MAC.SHA1.value.size,
        mac=96,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_256 = MACParams(
        code='hmac-sha2-256',
        size=MAC.SHA2_256.value.size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA2_512 = MACParams(
        code='hmac-sha2-512',
        size=MAC.SHA2_512.value.size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_MD5 = MACParams(
        code='hmac-md5',
        size=MAC.MD5.value.size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_MD5_96 = MACParams(
        code='hmac-md5-96',
        size=MAC.MD5.value.size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_64_OPENSSH_COM = MACParams(
        code='umac-64@openssh.com',
        size=MAC.UMAC_64.value.size,
        mac=MAC.UMAC_64,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    UMAC_128_OPENSSH_COM = MACParams(
        code='umac-128@openssh.com',
        size=MAC.UMAC_128.value.size,
        mac=MAC.UMAC_128,
        mode=MACMode.ENCRYPT_AND_MAC,
    )
    HMAC_SHA1_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha1-etm@openssh.com',
        size=MAC.SHA1.value.size,
        mac=MAC.SHA1,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA1_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha1-96-etm@openssh.com',
        size=MAC.SHA1.value.size,
        mac=96,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA2_256_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-256-etm@openssh.com',
        size=MAC.SHA2_256.value.size,
        mac=MAC.SHA2_256,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_SHA2_512_ETM_OPENSSH_COM = MACParams(
        code='hmac-sha2-512-etm@openssh.com',
        size=MAC.SHA2_512.value.size,
        mac=MAC.SHA2_512,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_MD5_ETM_OPENSSH_COM = MACParams(
        code='hmac-md5-etm@openssh.com',
        size=MAC.MD5.value.size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    HMAC_MD5_96_ETM_OPENSSH_COM = MACParams(
        code='hmac-md5-96-etm@openssh.com',
        size=MAC.MD5.value.size,
        mac=MAC.MD5,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    UMAC_64_ETM_OPENSSH_COM = MACParams(
        code='umac-64-etm@openssh.com',
        size=MAC.UMAC_64.value.size,
        mac=MAC.UMAC_64,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )
    UMAC_128_ETM_OPENSSH_COM = MACParams(
        code='umac-128-etm@openssh.com',
        size=MAC.UMAC_128.value.size,
        mac=MAC.UMAC_128,
        mode=MACMode.ENCRYPT_THEN_MAC,
    )


class SshKexAlgorithms(StringEnum, enum.Enum):
    DIFFIE_HELLMAN_GROUP1_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group1-sha1',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP14_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group14-sha1',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP14_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group14-sha256',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP14_SHA256_SSH_COM = KexAlgorithmParams(
        code='diffie-hellman-group14-sha256@ssh.com',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP16_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group16-sha512',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP18_SHA512 = KexAlgorithmParams(
        code='diffie-hellman-group18-sha512',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha1',
        kex=KeyExchange.DHE,
    )
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = KexAlgorithmParams(
        code='diffie-hellman-group-exchange-sha256',
        kex=KeyExchange.DHE,
    )
    ECDH_SHA2_NISTP256 = KexAlgorithmParams(
        code='ecdh-sha2-nistp256',
        kex=KeyExchange.ECDHE,
    )
    ECDH_SHA2_NISTP384 = KexAlgorithmParams(
        code='ecdh-sha2-nistp384',
        kex=KeyExchange.ECDHE,
    )
    ECDH_SHA2_NISTP521 = KexAlgorithmParams(
        code='ecdh-sha2-nistp521',
        kex=KeyExchange.ECDHE,
    )
    CURVE25519_SHA256 = KexAlgorithmParams(
        code='curve25519-sha256',
        kex=None, #FIXME
    )
    CURVE25519_SHA256_LIBSSH_ORG = KexAlgorithmParams(
        code='curve25519-sha256@libssh.org',
        kex=None, #FIXME
    )
    GSS_GEX_SHA1_ = KexAlgorithmParams(
        code='gss-gex-sha1_',
        kex=None, #FIXME
    )
    GSS_GROUP1_SHA1_ = KexAlgorithmParams(
        code='gss-group1-sha1_',
        kex=None, #FIXME
    )
    GSS_GROUP14_SHA1_ = KexAlgorithmParams(
        code='gss-group14-sha1_',
        kex=None, #FIXME
    )
    GSS_GROUP14_SHA256_ = KexAlgorithmParams(
        code='gss-group14-sha256_',
        kex=None, #FIXME
    )
    GSS_GROUP16_SHA512_ = KexAlgorithmParams(
        code='gss-group16-sha512_',
        kex=None, #FIXME
    )
    GSS_NISTP256_SHA256_ = KexAlgorithmParams(
        code='gss-nistp256-sha256_',
        kex=None, #FIXME
    )
    GSS_CURVE25519_SHA256_ = KexAlgorithmParams(
        code='gss-curve25519-sha256_',
        kex=None, #FIXME
    )


class SshHostKeyAlgorithmFactory(StringEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshHostKeyAlgorithms


class SshHostKeyType(enum.Enum):
    KEY = enum.auto()
    CERTIFICATE = enum.auto()
    X509_CERTIFICATE = enum.auto()


class SshHostKeyAlgorithms(StringEnum, enum.Enum):
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
    RSA_SHA2_512 = HostKeyAlgorithmParams(
        code='rsa-sha2-512',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.RSA,
    )
    SSH_DSS = HostKeyAlgorithmParams(
        code='ssh-dss',
        key_type=SshHostKeyType.KEY,
        authentication=Authentication.DSS,
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
    SSH_RSA_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-rsa-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.RSA,
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
    SSH_ED25519_CERT_V01_OPENSSH_COM = HostKeyAlgorithmParams(
        code='ssh-ed25519-cert-v01@openssh.com',
        key_type=SshHostKeyType.CERTIFICATE,
        authentication=Authentication.EDDSA,
    )
    X509V3_SIGN_RSA = HostKeyAlgorithmParams(
        code='x509v3-sign-rsa',
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



class SshCompressionAlgorithms(StringEnum, enum.Enum):
    ZLIB_OPENSSH_COM = CompressionParams(
        code='zlib@openssh.com',
    )
    ZLIB = CompressionParams(
        code='zlib',
    )
    NONE = CompressionParams(
        code='none',
    )
