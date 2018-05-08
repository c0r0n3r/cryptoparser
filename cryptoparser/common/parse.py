#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import struct

import six

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
import cryptoparser.common.utils as utils


@six.add_metaclass(abc.ABCMeta)
class ParsableBase(object):
    @classmethod
    def parse_mutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        del parsable[:parsed_length]
        return parsed_object

    @classmethod
    def parse_immutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        unparsed_bytes = parsable[parsed_length:]
        return parsed_object, unparsed_bytes

    @classmethod
    def parse_exact_size(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        if len(parsable) > parsed_length:
            raise TooMuchData(parsed_length)

        return parsed_object

    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class ParserBase(object):
    def __init__(self, parsable):
        self._parsable = parsable
        self._parsed_length = 0
        self._parsed_values = dict()

    def keys(self):
        return self._parsed_values.keys()

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def parse_parsable(self, name, parsable_class):
        parsed_object, unparsed_bytes = parsable_class.parse_immutable(
            self._parsable[self._parsed_length:]
        )
        self._parsed_length += len(self._parsable) - self._parsed_length - len(unparsed_bytes)
        self._parsed_values[name] = parsed_object


class ParserText(ParserBase):
    def _check_separators(self, count_offset, separator, min_count, max_count):
        count = count_offset
        while count < len(self._parsable) and self._parsable[count:].startswith(separator):
            count += len(separator)
        count -= count_offset

        if count < min_count:
            #FIXME
            raise InvalidValue('', ParserBase, 'separator')
        if count > max_count:
            #FIXME
            raise InvalidValue('', ParserBase, 'separator')

        return count

    def parse_separator(self, separator, min_length=1, max_length=1):
        self._parsed_length += self._check_separators(self._parsed_length, separator, min_length, max_length)

    def _parse_numeric_array(self, name, item_num, separator, item_numeric_class):
        value = list()
        item_begin_offset = self._parsed_length
        item_offset = self._parsed_length
        while item_offset < len(self._parsable) and len(value) < item_num:
            if chr(self._parsable[item_offset]).isdigit():
                item_offset += 1
                continue

            value.append(item_numeric_class(self._parsable[item_begin_offset:item_offset]))

            if separator and item_offset != len(self._parsable):
                item_offset += self._check_separators(item_offset, separator, 1, 1)

            item_begin_offset = item_begin_offset

        self._parsed_length = item_offset
        self._parsed_values[name] = value

    def parse_numeric(self, name, numeric_class=int):
        self._parse_numeric_array(name, 1, [], numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def _parse_string_array(self, name, item_min_num, item_max_num, item_min_length, item_max_length):
        #FIXME parse array
        if item_min_length > self.unparsed_length:
            raise NotEnoughData(item_min_length - self.unparsed_length)

        if item_max_length is None:
            parsable_length = len(self._parsable) - self.parsed_length
        else:
            parsable_length = min(item_max_length, self.unparsed_length)

        value = self._parsable[self._parsed_length:self._parsed_length + parsable_length]
        if name:
            self._parsed_values[name] = value

        self._parsed_length += parsable_length

    def parse_string_by_length(self, name, min_length=1, max_length=None):
        self._parse_string_array(name, 1, 1, min_length, max_length)

    def _parse_string_by_separator(self, item_offset, separator, optional_sparator=False):
        item_end = self._parsable.find(separator, item_offset)
        if item_end < 0:
            if optional_sparator:
                item_end = len(self._parsable)
            else:
                raise InvalidValue()

        return self._parsable[item_offset:item_end]

    def parse_string_by_separator(self, name, separator, optional_sparator=False):
        value = self._parse_string_by_separator(self._parsed_length, separator, optional_sparator)

        self._parsed_values[name] = value
        self._parsed_length += len(value)

    def parse_string_array(self, name, separator):
        value = []
        value_length = 0

        while value_length < self.unparsed_length:
            item = self._parse_string_by_separator(self._parsed_length + value_length, separator, True)

            value.append(item)
            value_length += len(item) + len(separator)

        self._parsed_values[name] = value
        self._parsed_length += value_length


class ParserBinary(ParserBase):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size in self._INT_FORMATER_BY_SIZE:
            value = list()
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size):
                item_bytes = self._parsable[item_offset:item_offset + item_size]
                if item_size == 3:
                    item_bytes = b'\x00' + item_bytes

                item = struct.unpack(
                    self._INT_FORMATER_BY_SIZE[item_size],
                    item_bytes
                )[0]
                try:
                    value.append(item_numeric_class(item))
                except ValueError:
                    raise InvalidValue(item, item_numeric_class)
        else:
            raise NotImplementedError()

        self._parsed_length += item_num * item_size
        self._parsed_values[name] = value

    def parse_numeric(self, name, size, numeric_class=int):
        self._parse_numeric_array(name, 1, size, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        self._parse_numeric_array(name, item_num, item_size, numeric_class)

    def parse_bytes(self, name, size):
        if self.unparsed_length < size:
            raise NotEnoughData(bytes_needed=self._parsed_length + size)

        self._parsed_values[name] = self._parsable[self._parsed_length: self._parsed_length + size]
        self._parsed_length += size


    def _parse_parsable_derived(self, item_offset, item_classes, fallback_class=None):
        for item_class in item_classes:
            try:
                item, parsed_length = item_class._parse(self._parsable[item_offset:])
                break
            except InvalidValue:
                pass
        else:
            if fallback_class is not None:
                item, parsed_length = fallback_class._parse(self._parsable[item_offset:])
            else:
                raise ValueError(self._parsable[item_offset:])

        return item, parsed_length

    def _parse_parsable_derived_array(self, name, items_size, item_classes, fallback_class=None):
        if items_size > self.unparsed_length:
            raise NotEnoughData(bytes_needed=items_size - self.unparsed_length)

        items = []
        remaining_items_size = items_size

        while remaining_items_size > 0:
            remaining_bytes_offset = self._parsed_length + items_size - remaining_items_size
            item, parsed_length = self._parse_parsable_derived(remaining_bytes_offset, item_classes, fallback_class)

            items.append(item)
            remaining_items_size -= parsed_length

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_array(self, name, items_size, item_class):
        if self.unparsed_length < items_size:
            raise NotEnoughData(items_size)

        try:
            return self._parse_parsable_derived_array(name, items_size, [item_class, ])
        except ValueError as e:
            raise InvalidValue(e.args[0], item_class)

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = utils.get_leaf_classes(item_base_class)
        try:
            return self._parse_parsable_derived_array(name, items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            raise InvalidValue(e.args[0], item_base_class)

    def parse_parsable_derived(self, name, item_base_class, fallback_class=None):
        item_classes = utils.get_leaf_classes(item_base_class)
        item, parsed_length = self._parse_parsable_derived(self._parsed_length, item_classes, fallback_class)

        self._parsed_values[name] = item
        self._parsed_length += parsed_length


class ComposerBase(object):
    def __init__(self):
        self._composed = str()

    def compose_parsable(self, value):
        self._composed += value.compose()

    def compose_parsable_array(self, values):
        composed = type(self._composed)()

        for item in values:
            composed += item.compose()

        self._composed += composed

    @property
    def composed(self):
        return type(self._composed)(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)


class ComposerText(ComposerBase):
    def __init__(self):
        self._composed = str()

    def _compose_numeric_array(self, values, separator):
        composed_str = str()

        for value in values:
            composed_str += '{:d}{}'.format(value, separator)

        self._composed += composed_str[:len(composed_str) - len(separator)]

    def compose_numeric(self, value):
        self._compose_numeric_array([value, ], separator='')

    def compose_string(self, value):
        self._composed += value

    def compose_separator(self, value):
        self.compose_string(value)


class ComposerBinary(ComposerBase):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def __init__(self):
        self._composed = bytearray()

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self._INT_FORMATER_BY_SIZE[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error:
                raise InvalidValue(value, int)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_bytes(self, value):
        self._composed += value
