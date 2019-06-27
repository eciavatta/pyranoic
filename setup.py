from setuptools import setup, find_packages

setup(
    name='flags-hunter',
    version='0.1',
    packages=['fg', 'fg.presets'],
    package_data={'fg': ['misc/*']},
    include_package_data=True,
    install_requires=[
        'click',
        'scapy',
        'watchdog',
        'dateparser',
        'CaseInsensitiveDict'
    ],
    entry_points='''
        [console_scripts]
        flags-hunter=fg.main:cli
    ''',
)
