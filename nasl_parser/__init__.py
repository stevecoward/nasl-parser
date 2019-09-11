import re
from datetime import datetime
from nasl_parser.fieldtypes import SingleNumericType, GenericTextType,\
    LocalizedTextType, MultiStringType, MultiNumericType, GenericDictType, \
    GenericListType, GenericDateTimeType, VersionType


class NaslScriptMethodParams(object):
    def __init__(self, var, val):
        val = val[0] if len(val) == 1 else val
        if var in ['id']:
            self.param = SingleNumericType(val)
        elif var in ['set_cvss_base_vector',
                     'set_cvss_temporal_vector',
                     'script_set_cvss3_base_vector',
                     'script_set_cvss3_temporal_vector',
                     'category']:
            self.param = GenericTextType(val)
        elif var in ['name', 'summary', 'family', 'copyright']:
            self.param = LocalizedTextType(val)
        elif var in ['cve_id']:
            self.param = MultiStringType(val)
        elif var in ['bugtraq_id', 'osvdb_id', 'cwe_id']:
            self.param = MultiNumericType(val)
        elif var in ['xref', 'set_attribute']:
            self.param = GenericDictType(val)
        elif var in ['check']:
            self.param = GenericListType(val)
        elif var in ['cvs_date']:
            self.param = GenericDateTimeType(val)
        elif var in ['version']:
            self.param = VersionType(val)
        else:
            self.param = None


class NaslScript(object):

    def __init__(self, contents):
        self.id = 0
        self.name = ''
        self.summary = ''
        self.version = ''
        self.check = []
        self.cvs_date = ''
        self.cve_id = []
        self.cwe_id = []
        self.bugtraq_id = []
        self.osvdb_id = []
        self.family = ''
        self.copyright = ''
        self.xref = {}
        self.set_attribute = {}
        self.set_cvss_base_vector = ''
        self.set_cvss_temporal_vector = ''
        self.set_cvss3_base_vector = ''
        self.set_cvss3_temporal_vector = ''
        self.category = ''
        contents = contents.replace('\n', ' ')
        contents = contents.replace('"', '').replace('\'', '')
        while '  ' in contents:
            contents = contents.replace('  ', ' ')
        for var in dir(self):
            if not var.startswith('_'):
                pattern = re.compile('script_%(var)s\s?\(\s?(.*?)\)\s?;' % {'var': var})

                # not all keys exist in every file. gracefully skip
                try:
                    param_text = pattern.findall(contents)

                    if len(param_text):
                        script_method = NaslScriptMethodParams(var, param_text)
                        setattr(self, var, script_method.param.values)
                    else:
                        raise Exception('Unable to match regex pattern.')
                except Exception:
                    pass

                # Get the packages that are affected (Checks)
                pattern = re.compile('if \(rpm_%(var)s\s?\(\s?([^;]*)\)\) flag\+\+' % {'var': var})

                # not all keys exist in every file. gracefully skip
                try:
                    param_text = pattern.findall(contents)
                    if len(param_text):
                        script_method = NaslScriptMethodParams(var, param_text)
                        setattr(self, var, script_method.param.values)
                    else:
                        raise Exception('Unable to match regex pattern.')
                except Exception:
                    pass

    def to_dict(self, pretty=False):
        self.cvs_date = self.cvs_date.strftime('%Y-%m-%d %H:%M:%S') \
            if isinstance(self.cvs_date, datetime) else self.cvs_date
        return {
            'ID': self.id,
            'Name': self.name,
            'Summary': self.summary,
            'Version': self.version,
            'Checks': self.check,
            'CVS Date': self.cvs_date,
            'CVE IDs': self.cve_id,
            'CWE IDs': self.cwe_id,
            'Bugtraq IDs': self.bugtraq_id,
            'OSVDB IDs': self.osvdb_id,
            'Vulnerability Family': self.family,
            'Copyright': self.copyright,
            'XREFs': self.xref,
            'Attributes': self.set_attribute,
            'CVSS Base Vector': self.set_cvss_base_vector,
            'CVSS Temporal Vector': self.set_cvss_temporal_vector,
            'CVSS3 Base Vector': self.set_cvss3_base_vector,
            'CVSS3 Temporal Vector': self.set_cvss3_temporal_vector,
            'Category': self.category,
        } if pretty else {
            'id': self.id,
            'name': self.name,
            'summary': self.summary,
            'version': self.version,
            'checks': self.check,
            'cvs_date': self.cvs_date,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'bugtraq_id': self.bugtraq_id,
            'osvdb_id': self.osvdb_id,
            'family': self.family,
            'copyright': self.copyright,
            'xref': self.xref,
            'attributes': self.set_attribute,
            'cvss_base_vector': self.set_cvss_base_vector,
            'cvss_temporal_vector': self.set_cvss_temporal_vector,
            'cvss3_base_vector': self.set_cvss3_base_vector,
            'cvss3_temporal_vector': self.set_cvss3_temporal_vector,
            'category': self.category,
        }
