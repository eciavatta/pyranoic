from setuptools import setup, find_packages

setup(
    name='flags-hunter',
    version='0.1',
    packages=['fg', 'fg.presets'],
    data_files=[('misc', ['misc/evaluate-http.py', 'misc/evaluate-tcp.py', 'misc/evaluate-raw.py',
                          'misc/capture-http.pcap', 'misc/capture-tcp.pcap', 'misc/capture-raw.pcap'])],
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
