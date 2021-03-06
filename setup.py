from setuptools import setup

setup(
    name='pyranoic',
    version='0.1.0',
    packages=['pyranoic', 'pyranoic.presets'],
    data_files=[('misc', [
        'pyranoic/misc/evaluate-http.py',
        'pyranoic/misc/evaluate-tcp.py',
        'pyranoic/misc/evaluate-raw.py',
        'pyranoic/misc/capture-http.pcap',
        'pyranoic/misc/capture-tcp.pcap',
        'pyranoic/misc/capture-raw.pcap'
    ])],
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
