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


def read_packets(file_path, keep_packets=False, filters=None):
    from pyshark import FileCapture

    return FileCapture(file_path, keep_packets, filters)


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
    from re import match

    return match(regex_pattern, basename(file_path))
