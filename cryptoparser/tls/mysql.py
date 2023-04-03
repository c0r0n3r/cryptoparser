# -*- coding: utf-8 -*-

import abc
import enum
import six

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.base import Serializable, OneByteEnumComposer, OneByteEnumParsable
from cryptoparser.common.parse import ByteOrder, ComposerBinary, ParsableBase, ParserBinary
from cryptoparser.common.exception import NotEnoughData


class MySQLVersion(enum.IntEnum):
    MYSQL_9 = 0x09
    MYSQL_10 = 0x0a


class MySQLCapability(enum.IntEnum):
    CLIENT_LONG_PASSWORD = 0x00000001
    CLIENT_FOUND_ROWS = 0x00000002
    CLIENT_LONG_FLAG = 0x00000004
    CLIENT_CONNECT_WITH_DB = 0x00000008
    CLIENT_NO_SCHEMA = 0x00000010
    CLIENT_COMPRESS = 0x00000020
    CLIENT_ODBC = 0x00000040
    CLIENT_LOCAL_FILES = 0x00000080
    CLIENT_IGNORE_SPACE = 0x00000100
    CLIENT_PROTOCOL_41 = 0x00000200
    CLIENT_INTERACTIVE = 0x00000400
    CLIENT_SSL = 0x00000800
    CLIENT_IGNORE_SIGPIPE = 0x00001000
    CLIENT_TRANSACTIONS = 0x00002000
    CLIENT_RESERVED = 0x00004000
    CLIENT_SECURE_CONNECTION = 0x00008000
    CLIENT_MULTI_STATEMENTS = 0x00010000
    CLIENT_MULTI_RESULTS = 0x00020000
    CLIENT_PS_MULTI_RESULTS = 0x00040000
    CLIENT_PLUGIN_AUTH = 0x00080000
    CLIENT_CONNECT_ATTRS = 0x00100000
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
    CLIENT_SESSION_TRACK = 0x00800000
    CLIENT_DEPRECATE_EOF = 0x01000000


class MySQLStatusFlag(enum.IntEnum):
    SERVER_STATUS_IN_TRANS = 0x0001
    SERVER_STATUS_AUTOCOMMIT = 0x0002
    SERVER_MORE_RESULTS_EXISTS = 0x0008
    SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010
    SERVER_STATUS_NO_INDEX_USED = 0x0020
    SERVER_STATUS_CURSOR_EXISTS = 0x0040
    SERVER_STATUS_LAST_ROW_SENT = 0x0080
    SERVER_STATUS_DB_DROPPED = 0x0100
    SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200
    SERVER_STATUS_METADATA_CHANGED = 0x0400
    SERVER_QUERY_WAS_SLOW = 0x0800
    SERVER_PS_OUT_PARAMS = 0x1000
    SERVER_STATUS_IN_TRANS_READONLY = 0x2000
    SERVER_SESSION_STATE_CHANGED = 0x4000


@attr.s(frozen=True)
class MySQLCharacterSetParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(int))
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    collate_name = attr.ib(validator=attr.validators.instance_of(six.string_types))


class MySQLCharacterSetFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return MySQLCharacterSet

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class MySQLCharacterSet(OneByteEnumComposer, enum.Enum):
    BIG5 = MySQLCharacterSetParams(
        code=1,
        name='big5',
        collate_name='big5_chinese_ci',
    )
    DEC8 = MySQLCharacterSetParams(
        code=3,
        name='dec8',
        collate_name='dec8_swedish_ci',
    )
    CP850 = MySQLCharacterSetParams(
        code=4,
        name='cp850',
        collate_name='cp850_general_ci',
    )
    HP8 = MySQLCharacterSetParams(
        code=6,
        name='hp8',
        collate_name='hp8_english_ci',
    )
    KOI8R = MySQLCharacterSetParams(
        code=7,
        name='koi8r',
        collate_name='koi8r_general_ci',
    )
    LATIN1 = MySQLCharacterSetParams(
        code=8,
        name='latin1',
        collate_name='latin1_swedish_ci',
    )
    LATIN2 = MySQLCharacterSetParams(
        code=9,
        name='latin2',
        collate_name='latin2_general_ci',
    )
    SWE7 = MySQLCharacterSetParams(
        code=10,
        name='swe7',
        collate_name='swe7_swedish_ci',
    )
    ASCII = MySQLCharacterSetParams(
        code=11,
        name='ascii',
        collate_name='ascii_general_ci',
    )
    UJIS = MySQLCharacterSetParams(
        code=12,
        name='ujis',
        collate_name='ujis_japanese_ci',
    )
    SJIS = MySQLCharacterSetParams(
        code=13,
        name='sjis',
        collate_name='sjis_japanese_ci',
    )
    HEBREW = MySQLCharacterSetParams(
        code=16,
        name='hebrew',
        collate_name='hebrew_general_ci',
    )
    TIS620 = MySQLCharacterSetParams(
        code=18,
        name='tis620',
        collate_name='tis620_thai_ci',
    )
    EUCKR = MySQLCharacterSetParams(
        code=19,
        name='euckr',
        collate_name='euckr_korean_ci',
    )
    KOI8U = MySQLCharacterSetParams(
        code=22,
        name='koi8u',
        collate_name='koi8u_general_ci',
    )
    GB2312 = MySQLCharacterSetParams(
        code=24,
        name='gb2312',
        collate_name='gb2312_chinese_ci',
    )
    GREEK = MySQLCharacterSetParams(
        code=25,
        name='greek',
        collate_name='greek_general_ci',
    )
    CP1250 = MySQLCharacterSetParams(
        code=26,
        name='cp1250',
        collate_name='cp1250_general_ci',
    )
    GBK = MySQLCharacterSetParams(
        code=28,
        name='gbk',
        collate_name='gbk_chinese_ci',
    )
    LATIN5 = MySQLCharacterSetParams(
        code=30,
        name='latin5',
        collate_name='latin5_turkish_ci',
    )
    ARMSCII8 = MySQLCharacterSetParams(
        code=32,
        name='armscii8',
        collate_name='armscii8_general_ci',
    )
    UTF8 = MySQLCharacterSetParams(
        code=33,
        name='utf8',
        collate_name='utf8_general_ci',
    )
    UCS2 = MySQLCharacterSetParams(
        code=35,
        name='ucs2',
        collate_name='ucs2_general_ci',
    )
    CP866 = MySQLCharacterSetParams(
        code=36,
        name='cp866',
        collate_name='cp866_general_ci',
    )
    KEYBCS2 = MySQLCharacterSetParams(
        code=37,
        name='keybcs2',
        collate_name='keybcs2_general_ci',
    )
    MACCE = MySQLCharacterSetParams(
        code=38,
        name='macce',
        collate_name='macce_general_ci',
    )
    MACROMAN = MySQLCharacterSetParams(
        code=39,
        name='macroman',
        collate_name='macroman_general_ci',
    )
    CP852 = MySQLCharacterSetParams(
        code=40,
        name='cp852',
        collate_name='cp852_general_ci',
    )
    LATIN7 = MySQLCharacterSetParams(
        code=41,
        name='latin7',
        collate_name='latin7_general_ci',
    )
    CP1251 = MySQLCharacterSetParams(
        code=51,
        name='cp1251',
        collate_name='cp1251_general_ci',
    )
    UTF16 = MySQLCharacterSetParams(
        code=54,
        name='utf16',
        collate_name='utf16_general_ci',
    )
    UTF16LE = MySQLCharacterSetParams(
        code=56,
        name='utf16le',
        collate_name='utf16le_general_ci',
    )
    CP1256 = MySQLCharacterSetParams(
        code=57,
        name='cp1256',
        collate_name='cp1256_general_ci',
    )
    CP1257 = MySQLCharacterSetParams(
        code=59,
        name='cp1257',
        collate_name='cp1257_general_ci',
    )
    UTF32 = MySQLCharacterSetParams(
        code=60,
        name='utf32',
        collate_name='utf32_general_ci',
    )
    BINARY = MySQLCharacterSetParams(
        code=63,
        name='binary',
        collate_name='binary',
    )
    GEOSTD8 = MySQLCharacterSetParams(
        code=92,
        name='geostd8',
        collate_name='geostd8_general_ci',
    )
    CP932 = MySQLCharacterSetParams(
        code=95,
        name='cp932',
        collate_name='cp932_japanese_ci',
    )
    EUCJPMS = MySQLCharacterSetParams(
        code=97,
        name='eucjpms',
        collate_name='eucjpms_japanese_ci',
    )
    GB18030 = MySQLCharacterSetParams(
        code=248,
        name='gb18030',
        collate_name='gb18030_chinese_ci',
    )
    UTF8MB4 = MySQLCharacterSetParams(
        code=255,
        name='utf8mb4',
        collate_name='utf8mb4_0900_ai_ci',
    )


class MySQLPacketBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class MySQLRecord(ParsableBase):
    HEADER_SIZE = 4

    packet_number = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    packet_bytes = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable, byte_order=ByteOrder.LITTLE_ENDIAN)

        parser.parse_numeric('packet_length', 3)
        parser.parse_numeric('packet_number', 1)
        parser.parse_raw('packet_bytes', parser['packet_length'])

        return MySQLRecord(
            packet_number=parser['packet_number'],
            packet_bytes=parser['packet_bytes'],
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)

        composer.compose_numeric(len(self.packet_bytes), 3)
        composer.compose_numeric(self.packet_number, 1)
        composer.compose_raw(self.packet_bytes)

        return composer.composed_bytes


@attr.s
class MySQLHandshakeV10(MySQLPacketBase):  # pylint: disable=too-many-instance-attributes
    protocol_version = attr.ib(validator=attr.validators.in_(MySQLVersion))
    server_version = attr.ib(validator=attr.validators.instance_of(six.string_types))
    connection_id = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    auth_plugin_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    capabilities = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(MySQLCapability),
    ))
    character_set = attr.ib(
        default=MySQLCharacterSet.UTF8, validator=attr.validators.optional(attr.validators.in_(MySQLCharacterSet))
    )
    states = attr.ib(default={}, validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(MySQLStatusFlag),
    ))
    auth_plugin_data_2 = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of((bytes, bytearray))),
    )
    auth_plugin_name = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types))
    )

    MINIMUM_SIZE = 33

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.MINIMUM_SIZE:
            raise NotEnoughData(cls.MINIMUM_SIZE - len(parsable))

        parser = ParserBinary(parsable, byte_order=ByteOrder.LITTLE_ENDIAN)

        parser.parse_numeric('protocol_version', 1, MySQLVersion)
        parser.parse_string_null_terminated('server_version', 'ascii')
        parser.parse_numeric('connection_id', 4)
        parser.parse_raw('auth_plugin_data', 8)
        parser.parse_raw('filler', 1)
        del parser['filler']
        parser.parse_numeric_flags('capabilities', 2, MySQLCapability)
        parser.parse_parsable('character_set', MySQLCharacterSetFactory)
        parser.parse_numeric_flags('states', 2, MySQLStatusFlag)
        parser.parse_numeric_flags('capabilities_2', 2, MySQLCapability, shift_left=16)
        capabilities = set(parser['capabilities']) | set(parser['capabilities_2'])
        del parser['capabilities_2']

        parser.parse_numeric('auth_plugin_data_len', 1)
        auth_plugin_data_len = parser['auth_plugin_data_len']
        del parser['auth_plugin_data_len']

        parser.parse_raw('reserved', 10)
        del parser['reserved']

        if MySQLCapability.CLIENT_PLUGIN_AUTH in capabilities:
            if not auth_plugin_data_len:
                raise InvalidValue(auth_plugin_data_len, cls, 'auth_plugin_data_len')

            auth_plugin_data_2_len = auth_plugin_data_len - 8
            parser.parse_raw('auth_plugin_data_2', auth_plugin_data_2_len)

        if MySQLCapability.CLIENT_PLUGIN_AUTH in capabilities:
            parser.parse_string_null_terminated('auth_plugin_name', 'ascii')

        params = dict(parser)
        params['capabilities'] = capabilities

        return cls(**params), parser.parsed_length

    def compose(self):
        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)

        composer.compose_numeric(self.protocol_version, 1)
        composer.compose_string_null_terminated(self.server_version, 'ascii')
        composer.compose_numeric(self.connection_id, 4)

        composer.compose_raw(self.auth_plugin_data)

        composer.compose_raw(b'\x00')  # filler

        capabilities = [capability for capability in self.capabilities if capability.value < 2 ** 16]
        composer.compose_numeric_flags(capabilities, 2)

        capabilities_2 = [capability for capability in self.capabilities if capability.value >= 2 ** 16]
        composer.compose_parsable(self.character_set)
        composer.compose_numeric_flags(self.states, 2)
        composer.compose_numeric_flags(capabilities_2, 2, shift_right=16)

        if MySQLCapability.CLIENT_PLUGIN_AUTH in self.capabilities:
            auth_plugin_data_len = 8
            if self.auth_plugin_data_2:
                auth_plugin_data_len += len(self.auth_plugin_data_2)

            composer.compose_numeric(auth_plugin_data_len, 1)
        else:
            composer.compose_numeric(0, 1)

        composer.compose_raw(10 * b'\x00')  # reserved
        if self.auth_plugin_data_2:
            composer.compose_raw(self.auth_plugin_data_2)

        if MySQLCapability.CLIENT_PLUGIN_AUTH in self.capabilities:
            composer.compose_string_null_terminated(self.auth_plugin_name, 'ascii')

        return composer.composed_bytes


@attr.s
class MySQLHandshakeSslRequest(MySQLPacketBase):
    capabilities = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(MySQLCapability),
    ))
    max_packet_size = attr.ib(default=0xffff, validator=attr.validators.instance_of(six.integer_types))
    character_set = attr.ib(default=None, validator=attr.validators.optional(attr.validators.in_(MySQLCharacterSet)))

    MINIMUM_SIZE = 5

    def __attrs_post_init__(self):
        if MySQLCapability.CLIENT_PROTOCOL_41 in self.capabilities:
            if self.character_set is None:
                self.character_set = MySQLCharacterSet.UTF8
        else:
            if self.max_packet_size >= 2 ** 24:
                raise ValueError(self.max_packet_size)
            for capability in self.capabilities:
                if capability.value >= 2 ** 16:
                    raise ValueError(self.max_packet_size)

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.MINIMUM_SIZE:
            raise NotEnoughData(cls.MINIMUM_SIZE - len(parsable))

        parser = ParserBinary(parsable, byte_order=ByteOrder.LITTLE_ENDIAN)

        parser.parse_numeric_flags('capabilities', 2, MySQLCapability)
        if MySQLCapability.CLIENT_PROTOCOL_41 in parser['capabilities']:
            parser.parse_numeric_flags('capabilities_2', 2, MySQLCapability, shift_left=16)
            parser.parse_numeric('max_packet_size', 4)
            parser.parse_parsable('character_set', MySQLCharacterSetFactory)
            parser.parse_raw('reserved', 23)
            del parser['reserved']

            character_set = parser['character_set']
            capabilities = parser['capabilities'] | parser['capabilities_2']
        else:
            parser.parse_numeric('max_packet_size', 3)
            capabilities = parser['capabilities']
            character_set = None

        return cls(capabilities, parser['max_packet_size'], character_set), parser.parsed_length

    def compose(self):
        composer = ComposerBinary(byte_order=ByteOrder.LITTLE_ENDIAN)

        if MySQLCapability.CLIENT_PROTOCOL_41 in self.capabilities:
            composer.compose_numeric_flags(self.capabilities, 4)
            composer.compose_numeric(self.max_packet_size, 4)
            composer.compose_parsable(self.character_set)
            composer.compose_raw(23 * b'\x00')
        else:
            composer.compose_numeric_flags(self.capabilities, 2)
            composer.compose_numeric(self.max_packet_size, 3)

        return composer.composed_bytes
