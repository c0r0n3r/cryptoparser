#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import json
import math

from collections import OrderedDict

try:
    from collections.abc import MutableSequence  # only works on python 3.3+
except ImportError:  # pragma: no cover
    from collections import MutableSequence

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ParserText, ComposerText
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue


def _default(
        self,  # pylint: disable=unused-argument
        obj
):
    if isinstance(obj, enum.Enum) and hasattr(obj.value, '_asdict'):
        result = {obj.name: obj.value._asdict()}
    elif isinstance(obj, enum.Enum) and isinstance(obj.value, str):
        result = obj.value
    elif isinstance(obj, JSONSerializable) and hasattr(obj, 'as_json'):
        result = obj.as_json()
    elif hasattr(obj, '__dict__'):
        result = {name: value for name, value in obj.__dict__.items() if not name.startswith('_')}

    return result


_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class JSONSerializable(object):  # pylint: disable=too-few-public-methods
    def as_json(self):
        return json.dumps(OrderedDict(sorted(self.__dict__.items())))

    def __repr__(self):
        return self.as_json()


class VectorParamBase(object):  # pylint: disable=too-few-public-methods
    def __init__(self, min_byte_num, max_byte_num):
        self.min_byte_num = min_byte_num
        self.max_byte_num = max_byte_num

        self.item_num_size = int(math.log(self.max_byte_num, 2) / 8) + 1

    @abc.abstractmethod
    def get_item_size(self, item):
        raise NotImplementedError()


class VectorParamNumeric(VectorParamBase):  # pylint: disable=too-few-public-methods
    def __init__(self, item_size, min_byte_num, max_byte_num, numeric_class=int):
        super(VectorParamNumeric, self).__init__(min_byte_num, max_byte_num)

        self.item_size = item_size
        self.numeric_class = numeric_class

    def get_item_size(self, item):
        return self.item_size


class OpaqueParam(VectorParamNumeric):  # pylint: disable=too-few-public-methods
    def __init__(self, min_byte_num, max_byte_num):
        super(OpaqueParam, self).__init__(1, min_byte_num, max_byte_num)

    def get_item_size(self, item):
        return 1


class VectorParamString(VectorParamBase):  # pylint: disable=too-few-public-methods
    def __init__(self, min_byte_num, max_byte_num, separator=',', item_class=str, fallback_class=None):
        super(VectorParamString, self).__init__(min_byte_num, max_byte_num)

        self.separator = separator
        self.item_class = item_class
        self.fallback_class = fallback_class

    def get_item_size(self, item):
        return len(str(item))


class VectorParamParsable(VectorParamBase):  # pylint: disable=too-few-public-methods
    def __init__(self, item_class, min_byte_num, max_byte_num, fallback_class):
        super(VectorParamParsable, self).__init__(min_byte_num, max_byte_num)

        self.item_class = item_class
        self.fallback_class = fallback_class

    def get_item_size(self, item):
        return len(item.compose())


class VectorBase(JSONSerializable, ParsableBase, MutableSequence):
    def __init__(self, items):
        super(VectorBase, self).__init__()

        self._param = self.get_param()

        self._items_size = 0
        self._items = []

        for item in items:
            self._items.append(item)
            self._items_size += self._param.get_item_size(item)

        self._update_items_size(del_item=None, insert_item=None)

    def _update_items_size(self, del_item=None, insert_item=None):
        size_diff = 0

        if del_item is not None:
            size_diff -= self._param.get_item_size(del_item)
        if insert_item is not None:
            size_diff += self._param.get_item_size(insert_item)

        if self._items_size + size_diff < self._param.min_byte_num:
            raise NotEnoughData(self._param.min_byte_num)
        if self._items_size + size_diff > self._param.max_byte_num:
            raise TooMuchData(self._param.max_byte_num)

        self._items_size += size_diff

    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def __repr__(self):
        return "<{0} {1}>".format(self.__class__.__name__, self._items)

    def as_json(self):
        return self._items

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

    def __eq__(self, other):
        return self._items == other._items  # pylint: disable=protected-access

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

        composer.compose_numeric(len(self._items) * self._param.item_size, self._param.item_num_size)
        composer.compose_numeric_array(self._items, self._param.item_size)

        return composer.composed_bytes


class VectorString(VectorBase):
    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        header_parser = ParserBinary(parsable[:vector_param.item_num_size])

        header_parser.parse_numeric('item_byte_num', vector_param.item_num_size)

        body_parser = ParserText(
            parsable[vector_param.item_num_size:header_parser['item_byte_num'] + vector_param.item_num_size]
        )

        body_parser.parse_string_array(
            'items', vector_param.separator, vector_param.item_class
        )

        return cls(body_parser['items']), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        vector_param = self.get_param()

        body_composer = ComposerText()
        body_composer.compose_string(vector_param.separator.join([item.compose() for item in self._items]))

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self._param.item_num_size)

        return header_composer.composed + body_composer.composed


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
        try:
            parser.parse_parsable_array(
                'items',
                items_size=parser['item_byte_num'],
                item_class=vector_param.item_class
            )
        except NotEnoughData as e:
            raise NotEnoughData(e.bytes_needed)

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable_array(self._items)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self._param.item_num_size)

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
        header_composer.compose_numeric(len(body_composer.composed_bytes), self._param.item_num_size)

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

        for enum_item in cls.get_enum_class():
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


class NByteEnumComposer(object):
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


class StringEnumParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        enum_items = [
            enum_item
            for enum_item in cls.get_enum_class()
            if len(enum_item.value) <= len(parsable)
        ]
        enum_items.sort(key=lambda color: len(color.value.code), reverse=True)

        for enum_item in enum_items:
            try:
                value = str(parsable[:len(enum_item.value.code)], 'ascii')
                if enum_item.value.code == value:
                    return enum_item, len(enum_item.value.code)
            except UnicodeDecodeError:
                pass
        else:
            raise InvalidValue(parsable, cls, 'code')

    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class StringEnumComposer(object):
    def compose(self):
        return self.value.code
