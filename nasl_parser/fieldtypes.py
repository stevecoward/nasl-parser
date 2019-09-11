import re
from datetime import datetime


class RegexValueFinder(object):
    pattern = re.compile(r'.*')
    values = ''

    def __init__(self, value):
        self.values = self.pattern.findall(value)


class SingleNumericType(RegexValueFinder):
    def __init__(self, value):
        self.values = int(value)


class MultiNumericType(RegexValueFinder):
    def __init__(self, value):
        self.pattern = re.compile(r'(\d+)')
        RegexValueFinder.__init__(self, value)
        self.values = [int(value) for value in self.values]


class MultiStringType():
    def __init__(self, value):
        self.values = [item.strip() for item in value.split(',')]


class LocalizedTextType(RegexValueFinder):
    def __init__(self, value):
        self.pattern = re.compile(r'(\w+):(.+)')
        if isinstance(value, list):
            for item in value:
                RegexValueFinder.__init__(self, item)
                if len(self.values):
                    self.values = {
                        self.values[0][0]: self.values[0][1],
                    }
        else:
            RegexValueFinder.__init__(self, value)
            if len(self.values):
                self.values = {
                    self.values[0][0]: self.values[0][1],
                }


class GenericDictType(RegexValueFinder):
    def __init__(self, value):
        attributes = {}
        if not isinstance(value, list):
            value = [value]
        for attribute in value:
            attribute = attribute.strip()
            attribute = attribute.replace(',value', ', value')
            parsed_attribute = attribute.split(', value:')
            try:
                key_name = parsed_attribute[0].split(':')[1].strip()
                key_value = parsed_attribute[1].strip()
                if key_name in attributes:
                    if not isinstance(attributes[key_name], list):
                        attributes[key_name] = [attributes[key_name]]
                    attributes[key_name].append(key_value)
                else:
                    attributes.update({key_name: key_value})
            except Exception:
                pass
        self.values = attributes


class GenericListType(RegexValueFinder):
    def __init__(self, value):
        attributes = []
        if not isinstance(value, list):
            value = [value]

        def pack(parts):
            if len(parts) == 1:
                return parts
            elif len(parts):
                return {parts[0]: pack(parts[1:])}
            return parts

        for attribute in value:
            list_att = []
            for item in attribute.split(','):
                list_att.append(item.split(':')[1])

            attributes.append(list_att)

        self.values = attributes


class GenericDateTimeType(RegexValueFinder):
    def __init__(self, value):
        self.pattern = re.compile(r'\s+(.+)\s+')
        RegexValueFinder.__init__(self, value)
        self.values = datetime.strptime(self.values[0], '%Y/%m/%d %H:%M:%S')


class VersionType(RegexValueFinder):
    def __init__(self, value):
        self.pattern = re.compile(r'(\d+\.\d+)')
        RegexValueFinder.__init__(self, value)
        self.values = self.values[0]


class GenericTextType(RegexValueFinder):
    def __init__(self, value):
        self.pattern = re.compile(r'(.+)')
        RegexValueFinder.__init__(self, value)
        self.values = self.values[0]
