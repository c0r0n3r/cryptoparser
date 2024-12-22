# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import datetime
import enum
import json
import math
import types

import ipaddress

try:
    from collections.abc import MutableSequence  # only works on python 3.3+
except ImportError:  # pragma: no cover
    from collections import MutableSequence  # pylint: disable=deprecated-class

from collections import OrderedDict

import attr
import urllib3

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import Gradeable
from cryptodatahub.common.types import CryptoDataEnumCodedBase, CryptoDataParamsBase

from cryptoparser.common.parse import (
    ComposerBinary,
    ComposerText,
    ParsableBase,
    ParsableBaseNoABC,
    ParserBinary,
    ParserText,
)
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidType
from cryptoparser.common.utils import bytes_to_hex_string


def _default(
        self,  # pylint: disable=unused-argument
        obj
):
    result = Serializable._json_traverse(obj, Serializable._json_result)  # pylint: disable=protected-access
    return result


_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class SerializableTextEncoder():
    def __call__(self, obj, level):
        if isinstance(obj, str):
            string_result = obj
        else:
            string_result = str(obj)

        return False, string_result


class Serializable():  # pylint: disable=too-few-public-methods
    _MARKDOWN_RESULT_STRING_CLASSES = (
        ipaddress.IPv4Network,
        ipaddress.IPv6Network,
        urllib3.util.url.Url,
    )
    post_text_encoder = SerializableTextEncoder()

    @staticmethod
    def _filter_out_non_human_friendly(obj, dict_value, human_friendly_only):
        if not attr.has(type(obj)) or not human_friendly_only:
            return dict_value

        fields_dict = attr.fields_dict(type(obj))
        dict_value = OrderedDict([
            (name, value)
            for name, value in dict_value.items()
            if name not in fields_dict or fields_dict[name].metadata.get('human_friendly', True)
        ])

        return dict_value

    @staticmethod
    def _get_ordered_dict(dict_value, human_friendly_only=False):
        if attr.has(type(dict_value)):
            obj = dict_value
            dict_value = OrderedDict([
                (name, getattr(dict_value, name))
                for name, field in attr.fields_dict(type(dict_value)).items()
                if not name.startswith('_')
            ])
            dict_value = Serializable._filter_out_non_human_friendly(obj, dict_value, human_friendly_only)
            keys = dict_value.keys()
        elif isinstance(dict_value, OrderedDict):
            keys = dict_value.keys()
        elif isinstance(dict_value, dict):
            if all(isinstance(key, enum.Enum) for key in dict_value.keys()):
                keys = sorted(dict_value.keys(), key=lambda key: key.name)
            else:
                keys = sorted(dict_value.keys())
        elif hasattr(dict_value, '__dict__'):
            dict_value = dict_value.__dict__
            keys = sorted(filter(lambda key: not key.startswith('_'), dict_value.keys()))

        result = OrderedDict([
            (key, dict_value[key])
            for key in keys
        ])

        return result

    @staticmethod
    def _json_result(obj):
        if isinstance(obj, enum.Enum):
            if isinstance(obj.value, CryptoDataParamsBase):
                result = obj.name
            else:
                result = {obj.name: obj.value}
        elif isinstance(obj, (str, int, float, bool, )) or obj is None:
            result = obj
        elif isinstance(obj, (bytes, bytearray)):
            result = bytes_to_hex_string(obj, separator=':', lowercase=False)
        else:
            result = str(obj)

        return result

    @staticmethod
    def _json_traverse(obj, result_func):
        if isinstance(obj, enum.Enum):
            result = result_func(obj)
        elif hasattr(obj, '_asdict'):
            result = Serializable._json_traverse(obj._asdict(), result_func)
        elif isinstance(obj, dict) or attr.has(type(obj)):
            result = OrderedDict([
                (
                    key.name if isinstance(key, enum.Enum) else Serializable._json_result(key),
                    Serializable._json_traverse(value, result_func)
                )
                for key, value in Serializable._get_ordered_dict(obj).items()
            ])
        elif hasattr(obj, '__dict__'):
            result = Serializable._json_traverse(obj.__dict__, result_func)
        elif isinstance(obj, (list, tuple, frozenset, set)):
            result = [Serializable._json_traverse(item, result_func) for item in obj]
        else:
            result = result_func(obj)

        return result

    @staticmethod
    def _markdown_indent_from_level(level):
        return 4 * level * ' '

    @classmethod
    def _markdown_human_readable_names(cls, obj, dict_value):
        name_dict = {}
        fields_dict = attr.fields_dict(type(obj)) if attr.has(type(obj)) else {}
        for name in dict_value:
            if isinstance(name, str):
                if name in fields_dict and 'human_readable_name' in fields_dict[name].metadata:
                    human_readable_name = fields_dict[name].metadata['human_readable_name']
                else:
                    human_readable_name = ' '.join(name.split('_')).title()
            else:
                post_text_encoder = cls.post_text_encoder
                cls.post_text_encoder = SerializableTextEncoder()
                _, human_readable_name = cls._markdown_result(name)
                cls.post_text_encoder = post_text_encoder

            name_dict[name] = human_readable_name

        return name_dict

    @classmethod
    def _markdown_result_complex(cls, obj, level=0):
        indent = Serializable._markdown_indent_from_level(level)

        if hasattr(obj, '_asdict'):
            dict_value = obj._asdict()
            if not isinstance(dict_value, dict):
                return False, dict_value

            dict_value = Serializable._filter_out_non_human_friendly(obj, dict_value, human_friendly_only=True)
        else:
            dict_value = Serializable._get_ordered_dict(obj, human_friendly_only=True)

        result = ''
        name_dict = cls._markdown_human_readable_names(obj, dict_value)
        for name, value in dict_value.items():
            result += f'{indent}* {name_dict[name]}'
            multiline, markdnow_result = cls._markdown_result(value, level + 1)
            if multiline:
                result += f':\n{markdnow_result}'
            else:
                result += f': {markdnow_result}\n'

        if not result:
            return False, '-'

        return True, result

    @classmethod
    def _markdown_result_list(cls, obj, level=0):
        if not obj:
            return False, '-'

        indent = Serializable._markdown_indent_from_level(level)

        result = ''
        for index, item in enumerate(obj):
            multiline, markdnow_result = cls._markdown_result(item, level + 1)
            separator = '\n' if multiline else ' '
            newline = '' if multiline else '\n'
            result += f'{indent}{index + 1}.{separator}{markdnow_result}{newline}'

        return True, result

    @staticmethod
    def _markdown_is_directly_printable(obj):
        return not isinstance(obj, enum.Enum) and isinstance(obj, (str, int, float, ))

    @classmethod
    def _markdown_result(cls, obj, level=0):  # pylint: disable=too-many-branches,too-many-return-statements
        if obj is None:
            result = cls.post_text_encoder('n/a', level)
        elif isinstance(obj, bool):
            result = cls.post_text_encoder('yes' if obj else 'no', level)
        elif Serializable._markdown_is_directly_printable(obj):
            result = cls.post_text_encoder(obj, level)
        elif isinstance(obj, Gradeable):
            result = cls.post_text_encoder(obj, level)
        elif isinstance(obj, Serializable):
            result = obj._as_markdown(level)  # pylint: disable=protected-access
        elif isinstance(obj, enum.Enum):
            if isinstance(obj.value, Serializable):
                return obj.value._as_markdown(level)  # pylint: disable=protected-access
            if isinstance(obj.value, CryptoDataParamsBase):
                return cls.post_text_encoder(obj.value, level)

            return cls.post_text_encoder(obj.name, level)
        elif isinstance(obj, cls._MARKDOWN_RESULT_STRING_CLASSES):
            return False, str(obj)
        elif isinstance(obj, datetime.timedelta):
            return False, str(obj.seconds)
        elif isinstance(obj, CryptoDataParamsBase) and hasattr(obj, '__str__'):
            return False, str(obj)
        elif attr.has(type(obj)):
            result = cls._markdown_result_complex(obj, level)
        elif hasattr(obj, '_asdict'):
            result = cls._markdown_result(obj._asdict(), level)
        elif hasattr(obj, '__dict__') or isinstance(obj, dict):
            result = cls._markdown_result_complex(obj, level)
        elif isinstance(obj, (list, tuple, frozenset, set, ArrayBase)):
            result = cls._markdown_result_list(obj, level)
        elif isinstance(obj, (bytes, bytearray)):
            result = cls.post_text_encoder(bytes_to_hex_string(obj, separator=':', lowercase=False), level)
        else:
            result = cls.post_text_encoder(obj, level)

        return result

    def _asdict(self):
        return Serializable._get_ordered_dict(self)

    def as_json(self):
        return json.dumps(self)

    def _as_markdown(self, level):
        return self._markdown_result_complex(self, level)

    def as_markdown(self):
        _, result = self._as_markdown(0)
        return result


@attr.s
class VariantParsableBase(ParsableBase):
    variant = attr.ib()

    _REGISTERED_VARIANTS = OrderedDict()

    @classmethod
    @abc.abstractmethod
    def _get_variants(cls):
        raise NotImplementedError()

    @variant.validator
    def _validator_variant(self, _, value):
        for variant_type in self._get_variant_types():
            if issubclass(variant_type, NByteEnumParsable):
                variant_type = variant_type.get_enum_class()

            if isinstance(value, variant_type):
                break
        else:
            raise InvalidValue(value, VariantParsable)

    @classmethod
    def _get_variant_types(cls):
        variant_types = []

        for variant_type_list in list(cls._get_variants().values()) + list(cls._get_registered_variants().values()):
            variant_types.extend(variant_type_list)

        return variant_types

    @classmethod
    def _get_registered_variants(cls):
        if cls not in cls._REGISTERED_VARIANTS:
            cls._REGISTERED_VARIANTS[cls] = OrderedDict()

        return cls._REGISTERED_VARIANTS[cls]

    @classmethod
    def register_variant_parser(cls, variant_tag, parsable_class):
        registered_variants = cls._get_registered_variants()
        if variant_tag not in registered_variants:
            registered_variants[variant_tag] = []

        registered_variants[variant_tag].append(parsable_class)

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    def compose(self):
        return self.variant.compose()


class VariantParsable(VariantParsableBase):
    @classmethod
    @abc.abstractmethod
    def _get_variants(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        for variant_parser in cls._get_variant_types():
            try:
                parsed_object, parsed_length = variant_parser.parse_immutable(parsable)
                return parsed_object, parsed_length
            except InvalidType:
                pass

        raise InvalidValue(parsable, cls)


class VariantParsableExact(VariantParsableBase):
    @classmethod
    @abc.abstractmethod
    def _get_variants(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        for variant_parser in cls._get_variant_types():
            try:
                parsed_object = variant_parser.parse_exact_size(parsable)
                return parsed_object, len(parsable)
            except (InvalidType, InvalidValue, TooMuchData):
                pass

        raise InvalidValue(parsable, cls)


@attr.s
class VectorParamBase():  # pylint: disable=too-few-public-methods
    min_byte_num = attr.ib(validator=attr.validators.instance_of(int))
    max_byte_num = attr.ib(validator=attr.validators.instance_of(int))
    item_num_size = attr.ib(init=False, validator=attr.validators.instance_of(int))

    def __attrs_post_init__(self):
        self.item_num_size = int(math.log(self.max_byte_num, 2) / 8) + 1

        attr.validate(self)

    @abc.abstractmethod
    def get_item_size(self, item):
        raise NotImplementedError()


@attr.s
class VectorParamNumeric(VectorParamBase):  # pylint: disable=too-few-public-methods
    item_size = attr.ib(validator=attr.validators.instance_of(int))
    numeric_class = attr.ib(default=int, validator=attr.validators.instance_of(type))

    def get_item_size(self, item):
        return self.item_size


@attr.s(init=False)
class OpaqueParam(VectorParamNumeric):  # pylint: disable=too-few-public-methods
    def __init__(self, min_byte_num, max_byte_num):
        super().__init__(min_byte_num, max_byte_num, 1)

    def get_item_size(self, item):
        return 1


@attr.s
class VectorParamString(VectorParamBase):  # pylint: disable=too-few-public-methods
    separator = attr.ib(validator=attr.validators.instance_of(str), default=',')
    encoding = attr.ib(validator=attr.validators.instance_of(str), default='ascii')
    item_class = attr.ib(validator=attr.validators.instance_of((type, types.FunctionType)), default=str)
    fallback_class = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of((type, types.FunctionType)))
    )

    def get_item_size(self, item):
        if isinstance(item, (ParsableBase, StringEnumParsable)):
            return len(item.compose())
        if isinstance(item, CryptoDataEnumCodedBase):
            return item.value.get_code_size()
        if isinstance(item, str):
            return len(item)

        raise NotImplementedError(type(item))


@attr.s
class VectorParamParsable(VectorParamBase):  # pylint: disable=too-few-public-methods
    item_class = attr.ib(validator=attr.validators.instance_of((type, types.FunctionType)))
    fallback_class = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of((type, types.FunctionType)))
    )

    def get_item_size(self, item):
        return len(item.compose())


@attr.s
class VectorParamEnumCodeNumeric(VectorParamBase):  # pylint: disable=too-few-public-methods
    item_class = attr.ib(validator=attr.validators.instance_of((type, types.FunctionType)))
    fallback_class = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of((type, types.FunctionType)))
    )

    def get_item_size(self, item):
        return self.fallback_class.get_byte_num()


@attr.s
class VectorParamEnumCodeString(VectorParamBase):  # pylint: disable=too-few-public-methods
    item_class = attr.ib(validator=attr.validators.instance_of((type, types.FunctionType)))
    fallback_class = attr.ib(init=False, default=None)

    def get_item_size(self, item):
        return len(item.value.code)


@attr.s
class ArrayBase(ParsableBase, MutableSequence, Serializable):
    _items = attr.ib()
    _items_size = attr.ib(init=False, default=0)
    param = attr.ib(init=False, default=None)

    def __attrs_post_init__(self):
        items = self._items

        self.param = self.get_param()
        self._items = []

        for item in items:
            self._items.append(item)
            self._items_size += self.param.get_item_size(item)

        self._update_items_size(del_item=None, insert_item=None)

        attr.validate(self)

    def _update_items_size(self, del_item=None, insert_item=None):
        size_diff = 0

        if del_item is not None:
            size_diff -= self.param.get_item_size(del_item)
        if insert_item is not None:
            size_diff += self.param.get_item_size(insert_item)

        if self._items_size + size_diff < self.param.min_byte_num:
            raise NotEnoughData(self.param.min_byte_num)
        if self._items_size + size_diff > self.param.max_byte_num:
            raise TooMuchData(self.param.max_byte_num)

        self._items_size += size_diff

    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def __len__(self):
        return len(self._items)

    def __getitem__(self, index):
        return self._items[index]

    def __delitem__(self, index):
        self._update_items_size(del_item=self._items[index])

        del self._items[index]

    def __setitem__(self, index, value):
        self._update_items_size(del_item=self._items[index], insert_item=value)
        self._items[index] = value

    def __str__(self):
        return str(self._items)

    def insert(self, index, value):
        self._update_items_size(insert_item=value)

        self._items.insert(index, value)

    def append(self, value):
        self.insert(len(self._items), value)

    def _asdict(self):
        return self._items

    def _as_markdown(self, level):
        return self._markdown_result(self._asdict(), level)


class Vector(ArrayBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()
        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)

        item_byte_num = parser['item_byte_num']
        item_num = int(item_byte_num / vector_param.item_size)
        parser.parse_numeric_array('items', item_num, vector_param.item_size, vector_param.numeric_class)

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(len(self._items) * self.param.item_size, self.param.item_num_size)
        composer.compose_numeric_array(self._items, self.param.item_size)

        return composer.composed_bytes


class VectorString(ArrayBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        header_parser = ParserBinary(parsable[:vector_param.item_num_size])

        header_parser.parse_numeric('item_byte_num', vector_param.item_num_size)

        if header_parser['item_byte_num'] == 0:
            return cls([]), header_parser.parsed_length

        body_parser = ParserText(
            parsable[vector_param.item_num_size:header_parser['item_byte_num'] + vector_param.item_num_size]
        )

        body_parser.parse_string_array(
            'items', vector_param.separator, vector_param.item_class, vector_param.fallback_class,
        )

        return cls(body_parser['items']), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        vector_param = self.get_param()

        body_composer = ComposerText(vector_param.encoding)
        body_composer.compose_parsable_array(self._items, vector_param.separator, vector_param.fallback_class)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed + body_composer.composed


class VectorParsable(ArrayBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)
        parser.parse_parsable_array(
            'items',
            items_size=parser['item_byte_num'],
            item_class=vector_param.item_class,
            fallback_class=vector_param.fallback_class
        )

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable_array(self._items)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorEnumCodeNumeric(VectorParsable):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def compose(self):
        body_composer = ComposerBinary()

        for item in self:
            if isinstance(self.param.fallback_class, type) and isinstance(item, self.param.fallback_class):
                body_composer.compose_parsable(item)
            else:
                body_composer.compose_numeric_enum_coded(item)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorEnumCodeString(VectorParsable):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def compose(self):
        body_composer = ComposerBinary()

        item_size = self.get_param().item_class.get_param().item_num_size
        for item in self:
            body_composer.compose_string_enum_coded(item, item_size)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorParsableDerived(ArrayBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)
        parser.parse_parsable_derived_array(
            'items',
            items_size=parser['item_byte_num'],
            item_base_class=vector_param.item_class,
            fallback_class=vector_param.fallback_class
        )

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable_array(self._items)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(len(body_composer.composed_bytes), self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class Opaque(ArrayBase):
    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', cls.get_param().item_num_size)
        parser.parse_raw('items', parser['item_byte_num'])

        items = parser['items']
        return cls([ord(items[i:i + 1]) for i in range(len(items))]), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(len(self._items), self.get_param().item_num_size)
        composer.compose_numeric_array(self._items, 1)

        return composer.composed_bytes

    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()


class NByteEnumParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('code', cls.get_byte_num())

        for enum_item in list(cls.get_enum_class()):
            if enum_item.value.code == parser['code']:
                return enum_item, cls.get_byte_num()

        raise InvalidValue(parser['code'], cls, 'code')

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class OneByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 1

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class TwoByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 2

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class ThreeByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 3

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class FourByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 4

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class NByteEnumComposer(enum.Enum):
    def __repr__(self):
        return self.__class__.__name__ + '.' + self.name

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(
            self.value.code,  # pylint: disable=no-member
            self.get_byte_num()
        )

        return composer.composed

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()


class OneByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 1


class TwoByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 2


class ThreeByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 3


class FourByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 4


class StringEnumParsableBase(ParsableBaseNoABC):
    @classmethod
    @abc.abstractmethod
    def _code_eq(cls, item_code, parsed_code):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        enum_items = [
            enum_item
            for enum_item in cls  # pylint: disable=not-an-iterable
            if len(enum_item.value.code) <= len(parsable)
        ]
        enum_items.sort(key=lambda color: len(color.value.code), reverse=True)

        try:
            code = bytes(parsable).decode('ascii')
        except UnicodeDecodeError as e:
            raise InvalidValue(parsable, cls) from e

        for enum_item in enum_items:
            if cls._code_eq(enum_item.value.code, code[:len(enum_item.value.code)]):
                return enum_item, len(enum_item.value.code)

        raise InvalidValue(parsable, cls, 'code')

    def compose(self):
        return self._asdict().encode('ascii')

    def _asdict(self):
        return getattr(self, 'value').code


class StringEnumParsable(StringEnumParsableBase):
    @classmethod
    def _code_eq(cls, item_code, parsed_code):
        return item_code == parsed_code


class StringEnumCaseInsensitiveParsable(StringEnumParsableBase):
    @classmethod
    def _code_eq(cls, item_code, parsed_code):
        return item_code.lower() == parsed_code.lower()


class ProtocolVersionBase(Serializable, ParsableBase, metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def __str__(self):
        raise NotImplementedError()

    def _asdict(self):
        return self.identifier

    def _as_markdown(self, level):
        return self._markdown_result(str(self), level)


@attr.s
class ProtocolVersionMajorMinorBase(ProtocolVersionBase):
    _SIZE = 2

    major = attr.ib()
    minor = attr.ib()

    @classmethod
    def _parse_version_numbers(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(bytes_needed=cls._SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('major', 1)
        parser.parse_numeric('minor', 1)

        return parser

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_version_numbers(parsable)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.major, 1)
        composer.compose_numeric(self.minor, 1)

        return composer.composed_bytes

    @property
    def identifier(self):
        return f'{self.major}_{self.minor}'

    def __str__(self):
        return f'{self.major}.{self.minor}'


@attr.s
class ListParamParsable():  # pylint: disable=too-few-public-methods
    item_class = attr.ib(validator=attr.validators.instance_of(type))
    fallback_class = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(type)))
    separator_class = attr.ib(attr.validators.instance_of(ParsableBase))
    min_byte_num = attr.ib(init=False, default=0)
    max_byte_num = attr.ib(init=False, default=2 ** 16)
    item_num_size = attr.ib(init=False, default=0)

    def get_item_size(self, item):  # pylint: disable=no-self-use
        return len(item.compose())


class ListParsable(ArrayBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        list_param = cls.get_param()

        parser = ParserBinary(parsable)

        parser.parse_parsable_list(
            'items',
            item_class=list_param.item_class,
            fallback_class=list_param.fallback_class,
            separator_class=list_param.separator_class
        )

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        separator = bytearray(self.get_param().separator_class().compose())
        composer.compose_parsable_array(self._items, separator)
        composer.compose_raw(separator)
        if self._items:
            composer.compose_raw(separator)

        return composer.composed_bytes


class OpaqueEnumParsable(Vector):
    @classmethod
    def _parse(cls, parsable):
        opaque, parsed_length = super(OpaqueEnumParsable, cls)._parse(parsable)
        code = b''.join([bytes((opaque_item,)) for opaque_item in opaque]).decode(cls.get_encoding())

        try:
            parsed_object = next(iter([
                enum_item
                for enum_item in cls.get_enum_class()
                if enum_item.value.code == code
            ]))
        except StopIteration as e:
            raise InvalidValue(code, cls) from e

        return parsed_object, parsed_length

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()

    @classmethod
    def get_encoding(cls):
        return 'utf-8'


class OpaqueEnumComposer(enum.Enum):
    def __repr__(self):
        return self.__class__.__name__ + '.' + self.name

    def compose(self):
        composer = ComposerBinary()
        value = self.value.code.encode(self.get_encoding())  # pylint: disable=no-member

        composer.compose_bytes(value, 1)

        return composer.composed_bytes

    @classmethod
    def get_encoding(cls):
        return 'utf-8'


@attr.s
class NumericRangeParsableBase(ParsableBase, Serializable):
    value = attr.ib(validator=attr.validators.instance_of(int))

    @value.validator
    def _validator_variant(self, _, value):
        if value < self._get_value_min():
            raise InvalidValue(value, type(self))

        if value > self._get_value_max():
            raise InvalidValue(value, type(self))

    @classmethod
    @abc.abstractmethod
    def _get_value_min(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_max(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_length(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('value', cls._get_value_length())

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value, self._get_value_length())

        return composer.composed

    def __str__(self):
        return str(self.value)

    def _as_markdown(self, level):
        return self._markdown_result(str(self), level)
