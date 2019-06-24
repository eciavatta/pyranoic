"""
Tool utilities.
"""


def check_valid_path(ctx, _, path):
    from os.path import exists, join
    from .constants import PROJECT_CONFIG_FILENAME, PACKETS_DIRNAME, SERVICES_DIRNAME

    if (exists(join(path, PROJECT_CONFIG_FILENAME)) or
            exists(join(path, PACKETS_DIRNAME)) or
            exists(join(path, SERVICES_DIRNAME))):

        ctx.fail(f'Another project is present in {path}')
    return path


def check_valid_project(ctx, _, path):
    from os.path import exists, join
    from .constants import PROJECT_CONFIG_FILENAME, PACKETS_DIRNAME, SERVICES_DIRNAME

    if not (exists(join(path, PROJECT_CONFIG_FILENAME)) and
            exists(join(path, PACKETS_DIRNAME)) and
            exists(join(path, SERVICES_DIRNAME))):

        ctx.fail(f'Invalid or corrupted project in {path}')
    return path


def fatal_error(message):
    from click import echo

    echo(message, err=True)
    exit(-1)


def load_module(file_path):
    from importlib.util import spec_from_file_location, module_from_spec

    spec = spec_from_file_location("apply_module", file_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def read_packets(file_path):
    from scapy.all import rdpcap

    return rdpcap(file_path)


def service_path(project_path, service_name):
    from os.path import join
    from .constants import SERVICES_DIRNAME

    return join(project_path, SERVICES_DIRNAME, service_name)


def read_config(file_path):
    from configparser import ConfigParser

    config = ConfigParser()
    try:
        config.read(file_path)
    except Exception as e:
        fatal_error(str(e))

    return config


def write_config(config, file_path):
    try:
        with open(file_path, 'w') as config_file:
            config.write(config_file)
    except Exception as e:
        fatal_error(str(e))


def file_name_match(file_path, regex_pattern):
    from os.path import basename

    return regex_pattern.match(basename(file_path))


def pcap_name_to_timestamp(pcap_name, regex_pattern):
    from datetime import datetime
    from .constants import PCAP_DATETIME_FORMAT

    pcap_datetime = regex_pattern.match(pcap_name)[2]
    return datetime.strptime(pcap_datetime, PCAP_DATETIME_FORMAT).timestamp()


def list_packets_chunks(project_path):
    import re
    from os import listdir
    from os.path import join
    from .constants import PACKETS_DIRNAME, PCAP_REGEX_PATTERN

    pcap_regex_compiled = re.compile(PCAP_REGEX_PATTERN)
    captures = [f for f in listdir(join(project_path, PACKETS_DIRNAME)) if file_name_match(f, pcap_regex_compiled)]

    return sorted(captures, key=lambda capture_name: pcap_name_to_timestamp(capture_name, pcap_regex_compiled))


def list_chunks_between_timestamps(project_path, start_timestamp, end_timestamp):
    import re
    from .constants import PCAP_REGEX_PATTERN

    all_chunks = list_packets_chunks(project_path)
    pcap_regex_compiled = re.compile(PCAP_REGEX_PATTERN)
    chunks = []
    all_chunks_len = len(all_chunks)

    check_start = True
    for i in range(all_chunks_len):
        chunk_timestamp = pcap_name_to_timestamp(all_chunks[i], pcap_regex_compiled)

        if start_timestamp > chunk_timestamp:
            continue
        if check_start:
            if i-1 < 0:
                return chunks
            else:
                chunks.append(all_chunks[i-1])
                check_start = False
        if chunk_timestamp <= end_timestamp:
            chunks.append(all_chunks[i])
        else:
            return chunks


def reduce_chunk_files(project_path, chunks):
    """

    :param project_path:
    :param chunks:
    :return: Tuple<file_name, is_tmp_file> or None
    """

    from os.path import join
    from tempfile import mkstemp
    from .constants import PACKETS_DIRNAME

    if not chunks:
        return None
    elif len(chunks) == 1:
        return chunks[0], False

    tmp_file = mkstemp(suffix='.pcap')[1]
    with open(tmp_file, 'wb') as file:
        for chunk in chunks:
            with open(join(project_path, PACKETS_DIRNAME, chunk), 'rb') as chunk_file:
                file.write(chunk_file.read())

    return tmp_file, True


def timestamp2hex(timestamp, precision=10000):
    return '{:02x}'.format(int(timestamp * precision))


def hex2timestamp(hex_str, precision=10000):
    if type(hex_str) is str:
        return int(hex_str, 16) / precision
    else:
        return int(hex_str) / precision


def pack_string(b_str):
    import string
    from struct import pack

    if type(b_str) is bytes:
        text = b_str.decode()
    else:
        text = b_str

    result = ''
    for i in range(len(text)):
        if text[i] in string.ascii_letters + string.digits:
            result += text[i]
        else:
            result += pack('B', b_str[i]).decode()

    return result

