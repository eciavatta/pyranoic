
NORMAL = 0
SUSPICIOUS = 1
MARKED = 2
FILTERED_OUT = 3

STATES_MAP = {
    0: 'NORMAL',
    1: 'SUSPICIOUS',
    2: 'MARKED',
    3: 'FILTERED_OUT'
}

PROJECT_CONFIG_FILENAME = 'project.conf'
PACKETS_DIRNAME = 'packets'
SERVICES_DIRNAME = 'services'
SERVICE_CONFIG_FILENAME = 'service.conf'
APPLY_SCRIPT_FILENAME = 'apply-script.py'

CAPTURE_FILENAME = 'capture.pcap'
MAX_CAPTURE_FILESIZE = 64*1000

PCAP_REGEX_PATTERN = rf"^capture_(\d{{5}})_(\d{{14}})\.pcap$"
PCAP_DATETIME_FORMAT = '%Y%m%d%H%M%S'

