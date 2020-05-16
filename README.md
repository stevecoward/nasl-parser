# nasl-parser - NOT ACTIVELY MAINTAINED

### Description

nasl-parser provides a programmatic solution to accessing the contents of a Nessus NASL script. This was originally built to interpret all NASL scripts and store the plugin data in a relational database.


### Installation

```
pip install nasl_parser
```


```
python setup.py install
```

### Usage

```
import nasl_parser
file = r'C:\nasl\test.nasl'

dict_data = {}
with open(file) as fh:
    contents = fh.read()
parsed_data = nasl_parser.NaslScript(contents).to_dict()
```
