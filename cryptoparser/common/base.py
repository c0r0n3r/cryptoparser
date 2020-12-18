# -*- coding: utf-8 -*-

import abc
import enum
import json
import math

try:
    from collections.abc import MutableSequence  # only works on python 3.3+
except ImportError:  # pragma: no cover
    from collections import MutableSequence

from collections import OrderedDict

import attr

import six

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue, InvalidType


def _default(
        self,  # pylint: disable=unused-argument
        obj
):
    result = Serializable._json_traverse(obj, Serializable._json_result)  # pylint: disable=protected-access
    return result


_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class Serializable(object):  # pylint: disable=too-few-public-methods
    @staticmethod
    def _get_ordered_dict(dict_value):
        result = OrderedDict([
            (name, dict_value[name])
            for name in sorted(dict_value.keys())
            if not name.startswith('_')
        ])

        return result

    @staticmethod
    def _json_result(obj):
        if isinstance(obj, enum.Enum):
            result = {obj.name: obj.value}
        elif isinstance(obj, six.string_types + six.integer_types + (float, bool, )) or obj is None:
            result = obj
        else:
            result = repr(obj)

        return result

    @staticmethod
    def _json_traverse(obj, result_func):
        if isinstance(obj, enum.Enum):
            result = result_func(obj)
        elif isinstance(obj, dict):
            result = OrderedDict([
                (name, Serializable._json_traverse(value, result_func))
                for name, value in Serializable._get_ordered_dict(obj).items()
            ])
        elif hasattr(obj, '_asdict'):
            result = Serializable._json_traverse(obj._asdict(), result_func)
        elif hasattr(obj, '__dict__'):
            result = Serializable._json_traverse(obj.__dict__, result_func)
        elif isinstance(obj, (list, tuple)):
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
            if name in fields_dict and 'human_readable_name' in fields_dict[name].metadata:
                human_readable_name = fields_dict[name].metadata['human_readable_name']
            elif name.isupper():
                human_readable_name = name
            else:
                human_readable_name = ' '.join(name.split('_')).title()
            name_dict[name] = human_readable_name

        return name_dict

    def _markdown_result_dict(self, obj, level=0):
        indent = Serializable._markdown_indent_from_level(level)

        if isinstance(obj, dict):
            dict_value = Serializable._get_ordered_dict(obj)
        elif hasattr(obj, '_asdict'):
            dict_value = obj._asdict()
        if not isinstance(dict_value, dict):
            return False, dict_value

        result = ''
        name_dict = self._markdown_human_readable_names(obj, dict_value)
        for name, value in dict_value.items():
            result += '{indent}* {name}'.format(indent=indent, name=name_dict[name])
            multiline, markdnow_result = self._markdown_result_simple(value, level)
            if multiline:
                result += ':\n{result}'.format(result=markdnow_result)
            else:
                result += ': {result}\n'.format(result=markdnow_result)

        if not result:
            return False, '-'

        return True, result

    @staticmethod
    def _markdown_is_directly_printable(obj):
        return isinstance(obj, six.string_types + six.integer_types + (float, ))

    def _markdown_result_simple(self, value, level):
        if isinstance(value, Serializable):
            return value._as_markdown(level + 1)  # pylint: disable=protected-access

        return self._markdown_result(value, level + 1)

    def _markdown_result(self, obj, level=0):
        if obj is None:
            result = False, 'n/a'
        elif isinstance(obj, bool):
            result = False, 'yes' if obj else 'no'
        elif Serializable._markdown_is_directly_printable(obj):
            result = False, str(obj)
        elif isinstance(obj, enum.Enum):
            if isinstance(obj.value, Serializable):
                return self._markdown_result_simple(obj.value, level)

            return False, obj.name
        elif hasattr(obj, '__dict__') or isinstance(obj, dict):
            return self._markdown_result_dict(obj, level)
        elif isinstance(obj, (list, tuple)):
            if obj:
                indent = Serializable._markdown_indent_from_level(level)

                result = ''
                for index, item in enumerate(obj):
                    multiline, markdnow_result = self._markdown_result_simple(item, level)
                    result += '{indent} {index}.{separator}{value}{newline}'.format(
                        indent=indent,
                        index=index + 1,
                        separator='\n' if multiline else ' ',
                        value=markdnow_result,
                        newline='' if multiline else '\n',
                    )
                result = True, result
            else:
                return False, '-'
        else:
            result = False, repr(obj)

        return result

    def _asdict(self):
        result = Serializable._get_ordered_dict(self.__dict__)
        return result

    def as_json(self):
        return json.dumps(self)

    def _as_markdown(self, level):
        return self._markdown_result(self, level)

    def as_markdown(self):
        _, result = self._as_markdown(0)
        return result


@attr.s
class VariantParsable(ParsableBase):
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
    def _parse(cls, parsable):
        for variant_parser in cls._get_variant_types():
            try:
                parsed_object, parsed_length = variant_parser.parse_immutable(parsable)
                return parsed_object, parsed_length
            except InvalidType:
                pass

        raise InvalidValue(parsable, cls)

    def compose(self):
        return self.variant.compose()


@attr.s
class VectorParamBase(object):  # pylint: disable=too-few-public-methods
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
        super(OpaqueParam, self).__init__(min_byte_num, max_byte_num, 1)

    def get_item_size(self, item):
        return 1


@attr.s
class VectorParamParsable(VectorParamBase):  # pylint: disable=too-few-public-methods
    item_class = attr.ib(validator=attr.validators.instance_of(type))
    fallback_class = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(type)))

    def get_item_size(self, item):
        return len(item.compose())


@attr.s
class VectorBase(ParsableBase, MutableSequence):
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


class Vector(VectorBase):
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


class VectorParsable(VectorBase):
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


class VectorParsableDerived(VectorBase):
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


class Opaque(VectorBase):
    def __init__(self, items):
        if isinstance(items, (bytes, bytearray)):
            items = [ord(items[i:i + 1]) for i in range(len(items))]

        super(Opaque, self).__init__(items)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', cls.get_param().item_num_size)
        parser.parse_bytes('items', parser['item_byte_num'])

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


class NByteEnumComposer(enum.Enum):
    def __repr__(self):
        return self.__class__.__name__ + '.' + self.name

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(
            self.value.code,  # pylint: disable=no-member
            self.get_byte_num()
        )

        return composer.composed_bytes

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
