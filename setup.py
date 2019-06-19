from setuptools import setup, find_packages

setup(
    name='flags-hunter',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click',
        'scapy'
    ],
    entry_points='''
        [console_scripts]
        flags-hunter=fg.main:cli
    ''',
)
