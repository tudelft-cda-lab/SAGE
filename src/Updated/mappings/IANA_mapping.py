import csv
from typing import Dict

import requests

IANA_CSV_FILE = \
    "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"


class IANAMappingEntry:
    def __init__(self, name: str, description: str):
        self.name = name or "Unknown"
        self.description = description or "---"


def load_IANA_mapping(source=IANA_CSV_FILE) -> Dict[int, IANAMappingEntry]:
    """
    Download the IANA port-service mapping
    """
    response = requests.get(source)
    if response.ok:
        content = response.content.decode("utf-8")
    else:
        raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

    # Note: uncomment to use a pre-downloaded csv instead
    # f = open("../data/port_mappings_2021_01_18.csv", "r+")
    # table = csv.reader(f)

    # Drop headers (Service name, port, protocol, description, ...)
    headers = next(table)

    # Note that ports might have holes
    ports = {}
    for row in table:
        # Drop missing port number, Unassigned and Reserved ports
        if row[1] and 'Unassigned' not in row[3]:  # and 'Reserved' not in row[3]:

            # Split range in single ports
            if '-' in row[1]:
                low_port, high_port = map(int, row[1].split('-'))
            else:
                low_port = high_port = int(row[1])

            mapping = IANAMappingEntry(row[0], row[3])

            for port in range(low_port, high_port + 1):
                ports[port] = mapping
        else:
            # Do nothing
            pass

    return ports


IANA_mapping = load_IANA_mapping(IANA_CSV_FILE)
