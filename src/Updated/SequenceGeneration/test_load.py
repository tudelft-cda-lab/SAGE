from typing import Tuple

from src.Base.load import parse, removeDup
from src.Updated.SequenceGeneration.ParsedAlert import ParsedAlert
from src.Updated.SequenceGeneration.load import read_file, _parse, _remove_duplicate

FILE = "../../data/cptc_18/suricata_alert_t2.json"


def assert_equivalent(alert: ParsedAlert, tup: Tuple):
    assert alert.time_delta_seconds == tup[0]
    assert alert.src_ip == tup[1]
    assert alert.src_port == tup[2]
    assert alert.dest_ip == tup[3]
    assert alert.dest_port == tup[4]
    assert alert.signature == tup[5]
    assert alert.category == tup[6]
    assert alert.host == tup[7]
    assert alert.timestamp == tup[8]
    assert alert.mcat == tup[9]


def main():
    raw_data = read_file(FILE)

    print("Parsing original")
    parsed_base = parse(raw_data)

    print("Parsing update")
    parsed_update = _parse(raw_data)

    print(f"{len(parsed_base)} vs {len(parsed_update)}")
    assert len(parsed_base) == len(parsed_update)
    for i in range(len(parsed_base)):
        assert_equivalent(parsed_update[i], parsed_base[i])

    print("Removing duplicates")
    parsed_base = removeDup(parsed_base)
    parsed_update = _remove_duplicate(parsed_update)

    print(f"{len(parsed_base)} vs {len(parsed_update)}")
    if len(parsed_update) == len(parsed_base) + 1:
        # Note: Base.load.py: 166 -> removeDup skips index 0
        parsed_update = parsed_update[1:]
    assert len(parsed_base) == len(parsed_update)
    for i in range(len(parsed_base)):
        assert_equivalent(parsed_update[i], parsed_base[i])

    print("Done testing")


if __name__ == '__main__':
    main()
