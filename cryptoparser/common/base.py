#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import json
import math

from collections import MutableSequence
from typing import TypeVar

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue

T = TypeVar('T')

def _default(self, obj):
    if isinstance(obj, enum.Enum) and hasattr(obj.value, '_asdict'):
        return { obj.name: obj.value._asdict() }
    elif isinstance(obj, JSONSerializable) and hasattr(obj, 'as_json'):
        return obj.as_json()

    return { name: value for name, value in obj.__dict__.items() if not name.startswith('_') }

_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class JSONSerializable(object):
    def as_json(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return self.as_json()


class VectorParamBase(object):
    def __init__(self, min_byte_num, max_byte_num):
        self.min_byte_num = min_byte_num
        self.max_byte_num = max_byte_num

        self.item_num_size = int(math.log(self.max_byte_num, 2) / 8) + 1


class VectorParamNumeric(VectorParamBase):
    def __init__(self, item_size, min_byte_num, max_byte_num, numeric_class=int):
        super(VectorParamNumeric, self).__init__(min_byte_num, max_byte_num)

        self.item_size = item_size
        self.numeric_class = numeric_class

    def get_item_size(self, item):
        return self.item_size


class VectorParamParsable(VectorParamBase):
    def __init__(self, item_class, min_byte_num, max_byte_num, fallback_class):
        super(VectorParamParsable, self).__init__(min_byte_num, max_byte_num)

        self.item_class = item_class
        self.fallback_class = fallback_class

    def get_item_size(self, item):
        return len(item.compose())


class VectorBase(ParsableBase, MutableSequence):
    def __init__(self, items):
        # type: (Sequence[T], int, int, int) -> None
        super(ParsableBase, self).__init__()
        super(MutableSequence, self).__init__()

        self.param = self.get_param()

        self._items_size = 0
        self._items = []

        for item in items:
            self._items.append(item)
            self._items_size += self.param.get_item_size(item)

        self._update_items_size(del_item=None, insert_item=None)

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

    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def __repr__(self):
        return "<{0} {1}>".format(self.__class__.__name__, self._items)

    def __len__(self):
        # type: () -> int
        return len(self._items)

    def __getitem__(self, index):
        # type: (int) -> T
        return self._items[index]

    def __delitem__(self, index):
        # type: (int) -> None
        self._update_items_size(del_item=self._items[index])

        del self._items[index]

    def __setitem__(self, index, value):
        # type: (int, T) -> None
        self._update_items_size(del_item=self._items[index], insert_item=value)
        self._items[index] = value

    def __str__(self):
        # type: () -> str
        return str(self._items)

    def insert(self, index, value):
        # type: (int, T) -> None
        self._update_items_size(insert_item=value)

        self._items.insert(index, value)

    def append(self, value):
        # type: (int, T) -> None
        self.insert(len(self._items), value)


class Vector(VectorBase):
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
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorParsableDerived(VectorBase):
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


class Opaque(Vector):
    @classmethod
    def _parse(cls, parsable):
        composer = ComposerBinary()
        vector_param = cls.get_param()
        composer.compose_numeric(vector_param.min_byte_num, vector_param.item_num_size)

        try:
            vector, parsed_length = super(Opaque, cls)._parse(composer.composed_bytes + parsable)
        except NotEnoughData as e:
            raise NotEnoughData(cls.get_byte_num())

        return cls(vector._items), parsed_length - vector_param.item_num_size

    def compose(self):
        return super(Opaque, self).compose()[self.param.item_num_size:]

    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @classmethod
    def get_param(cls):
        byte_num = cls.get_byte_num()
        return VectorParamNumeric(item_size=1, min_byte_num=byte_num, max_byte_num=byte_num)


class NByteEnumParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('code', cls.get_byte_num())

        for enum_item in cls.get_enum_class():
            if enum_item.value.code == parser['code']:
                return enum_item, cls.get_byte_num()
        else:
            raise InvalidValue(parser['code'], cls, 'code')

    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class OneByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 1


class TwoByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 2


class ThreeByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 3


class NByteEnumComposer(object):
    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value.code, self.get_byte_num())

        return composer.composed_bytes


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
