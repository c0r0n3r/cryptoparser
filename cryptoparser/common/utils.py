#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect


def get_leaf_classes(base_class):

    def _get_subclasses(base_classes):
        subclasses = []
        for base_class in base_classes:
            subclasses += [subclass for subclass in base_class.__subclasses__() if not inspect.isabstract(subclass)]
        return subclasses

    result = []
    subclasses = [base_class, ]
    while subclasses:
        subclasses = _get_subclasses(subclasses)
        result += subclasses
    return result
