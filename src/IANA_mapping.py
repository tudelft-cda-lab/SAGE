import requests
import csv

IANA_CSV_FILE = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"


def load_IANA_mapping(source=IANA_CSV_FILE):
    """
    Download the IANA port-service mapping
    """
    response = requests.get(source)
    if response.ok:
        content = response.content.decode("utf-8")
    else:
        raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

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

            for port in range(low_port, high_port + 1):
                ports[port] = {
                    "name": row[0] if row[0] else "Unknown",
                    "description": row[3] if row[3] else "---",
                }
        else:
            # Do nothing
            pass

    return ports
