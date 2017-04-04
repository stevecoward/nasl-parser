import re
from fieldtypes import SingleNumericType, GenericTextType, LocalizedTextType, MultiStringType, MultiNumericType, GenericDictType

class NaslScriptMethodParams():
    def __init__(self, var, val):
        val = val[0] if len(val) == 1 else val
        if var in ['id']:
            self.param = SingleNumericType(val)
        elif var in ['version', 'cvs_date', 'set_cvss_base_vector', 'set_cvss_temporal_vector', 'script_set_cvss3_base_vector', 'script_set_cvss3_temporal_vector', 'category']:
            self.param = GenericTextType(val)
        elif var in ['name', 'summary', 'family', 'copyright']:
            self.param = LocalizedTextType(val)
        elif var in ['cve_id']:
            self.param = MultiStringType(val)
        elif var in ['bugtraq_id', 'osvdb_id', 'cwe_id']:
            self.param = MultiNumericType(val)
        elif var in ['xref', 'set_attribute']:
            self.param = GenericDictType(val)
        else:
            self.param = None

class NaslScript():
    id = 0
    name = ''
    summary = ''
    version = ''
    cvs_date = ''
    cve_id = []
    cwe_id = []
    bugtraq_id = []
    osvdb_id = []
    family = ''
    copyright = ''
    xref = {}
    set_attribute = {}
    set_cvss_base_vector = ''
    set_cvss_temporal_vector = ''
    set_cvss3_base_vector = ''
    set_cvss3_temporal_vector = ''
    category = ''

    def __init__(self, contents):
        contents = contents.replace('\n',' ').replace('"','').replace('  ', ' ')
        for var in dir(self):
            if not var.startswith('_'):
                pattern = re.compile('script_%(var)s\(([^;]*)\)' % {'var': var})

                # not all keys exist in every file. gracefully skip
                try:
                    param_text = pattern.findall(contents)
                    if len(param_text):
                        script_method = NaslScriptMethodParams(var, param_text)
                        setattr(self, var, script_method.param.values)
                    else:
                        raise Exception('Unable to match regex pattern.')
                except:
                    pass

    def _todict(self, pretty=False):
        return {
            'ID': self.id,
            'Name': self.name,
            'Summary': self.summary,
            'Version': self.version,
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
