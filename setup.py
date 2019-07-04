from setuptools import setup

setup(
    name='pyranoic',
    version='0.1.0',
    packages=['pyranoic', 'pyranoic.presets'],
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
        pyranoic=pyranoic.main:cli
    ''',
)
