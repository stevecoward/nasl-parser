import re
from fieldtypes import SingleNumericType, GenericTextType, LocalizedTextType, MultiStringType, MultiNumericType, GenericDictType

class NaslScriptMethodParams():
    def __init__(self, var, val):
        val = val[0] if len(val) == 1 else val
        if var == 'id':
            self.param = SingleNumericType(val)
        elif var in ['version', 'cvs_date', 'set_cvss_base_vector', 'set_cvss_temporal_vector', 'category']:
            self.param = GenericTextType(val)
        elif var in ['name', 'summary', 'family', 'copyright']:
            self.param = LocalizedTextType(val)
        elif var in ['cve_id']:
            self.param = MultiStringType(val)
        elif var in ['bugtraq_id', 'osvdb_id']:
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
    bugtraq_id = []
    osvdb_id = []
    family = ''
    copyright = ''
    xref = {}
    set_attribute = {}
    set_cvss_base_vector = ''
    set_cvss_temporal_vector = ''
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
