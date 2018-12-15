from distutils.core import setup

setup(
    name='nasl-parser',
    version='0.1.7',
    author='Steve Coward',
    author_email='steve.coward@gmail.com',
    url='https://github.com/stevecoward/nasl-parser',
    license='LICENSE',
    description='Parses a Nessus Script Language script plugin and extracts details from it.',
    install_requires=[
        'six',
    ],
    packages=['nasl_parser'],
)
