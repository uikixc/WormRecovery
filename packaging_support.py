"""Retain any certificate resource required by the selected Python runtime."""
from pathlib import Path
import ssl


def runtime_data_arguments():
    resource=Path(ssl.__file__).with_name('codex-rejected-cas.pem')
    return ['--add-data',str(resource)+':.'] if resource.is_file() else []


if __name__=='__main__':
    for argument in runtime_data_arguments():print(argument)
