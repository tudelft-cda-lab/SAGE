import datetime
import json
import glob
import os
from typing import List, Optional, Tuple

from src.Updated.MicroAttackStage import MicroAttackStage
from src.Updated.SequenceGeneration import ParsedAlert, is_duplicate_attack

# IP to be filtered out, seems to be constant
# from src.Updated.SequenceGeneration.ParsedAlert import
from src.Updated.mappings.mappings import get_attack_stage_mapping

BAD_IP = "169.254.169.254"

# Type hint to shorten the result of loading data
LoadedData = Tuple[List[List[ParsedAlert]], List[str]]


def read_file(filename: str, reverse=True):
    f = open(filename, "r")
    unparsed_data = json.load(f)
    f.close()
    if reverse:
        unparsed_data = unparsed_data[::-1]
    return unparsed_data


def load_data(folder: str, time_delta, dataset="CPTC'18") -> LoadedData:
    parsed_alerts = []
    team_labels = []
    files = glob.glob(folder + "/*.json")
    print('About to read json files...')

    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)
        team_labels.append(name)
        parsed = _parse(read_file(f), dataset=dataset, alert_labels=[])
        parsed = _remove_duplicate(parsed, time_delta=time_delta)
        parsed_alerts.append(parsed)

    return parsed_alerts, team_labels


def _parse(raw_data, dataset="CPTC'18", alert_labels=Optional[List[str]], filter_info_leak=False,
           slim=False):
    if alert_labels is None:
        alert_labels = []

    if dataset == "CPTC'18":
        parsed_data = _parse_cptc_18(raw_data)
    else:
        parsed_data = []

    # Add custom mcat based on alert labels. (copied from the base function)
    if slim:
        print(f"{len(parsed_data)} parsed records, {len(alert_labels)} pre-defined alert labels")
        j = 0
        for i, alert in enumerate(alert_labels):
            split = alert.split(",")
            source = split[0]
            dest = split[1]
            mcat = int(split[-1][:-1])
            category = split[2]
            if filter_info_leak and split[2] == 'Attempted Information Leak':
                continue
            if source == BAD_IP or dest == BAD_IP or category == 'Not Suspicious Traffic':
                continue

            if source == parsed_data[j].src_ip and dest == parsed_data[j].dest_ip:
                parsed_data[j].mcat = mcat
            j += 1

    return parsed_data


def _parse_cptc_18(raw_data, filter_info_leak=False) -> List[ParsedAlert]:
    """
    Parses one json file from the CPTC'18 dataset.

    :param raw_data: contents of the file through json.load
    :param filter_info_leak: flag to filter out all alerts with category
        "Attempted Information Leak"
    """
    result = []

    previous_timestamp = datetime.datetime.strptime(json.loads(raw_data[0]['_raw'])["timestamp"],
                                                    '%Y-%m-%dT%H:%M:%S.%f%z')
    for record in raw_data:
        # sample_record = {"_bkt": "ids~21~309B8BB8-F45C-44CE-ABE5-EF8B9EC8A780",
        #                  "_cd": "21:63905046",
        #                  "_indextime": "1541287800",
        #                  "_raw": "{\"timestamp\":\"2018-11-03T23:29:59.391761+0000\",\"flow_id\":1818990308865466,\"in_iface\":\"ens4\",\"event_type\":\"alert\",\"src_ip\":\"10.0.0.22\",\"src_port\":44350,\"dest_ip\":\"169.254.169.254\",\"dest_port\":80,\"proto\":\"TCP\",\"tx_id\":0,\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":2013031,\"rev\":6,\"signature\":\"ET POLICY Python-urllib\\/ Suspicious User Agent\",\"category\":\"Attempted Information Leak\",\"severity\":2},\"http\":{\"hostname\":\"metadata.google.internal\",\"url\":\"\\/computeMetadata\\/v1\\/instance\\/network-interfaces\\/?alt=json&last_etag=9db2cc14c6c04c17&recursive=True&timeout_sec=66&wait_for_change=True\",\"http_user_agent\":\"Python-urllib\\/3.6\",\"http_content_type\":\"application\\/json\",\"http_method\":\"GET\",\"protocol\":\"HTTP\\/1.1\",\"status\":200,\"length\":319},\"app_proto\":\"http\",\"payload\":\"R0VUIC9jb21wdXRlTWV0YWRhdGEvdjEvaW5zdGFuY2UvbmV0d29yay1pbnRlcmZhY2VzLz9hbHQ9anNvbiZsYXN0X2V0YWc9OWRiMmNjMTRjNmMwNGMxNyZyZWN1cnNpdmU9VHJ1ZSZ0aW1lb3V0X3NlYz02NiZ3YWl0X2Zvcl9jaGFuZ2U9VHJ1ZSBIVFRQLzEuMQ0KQWNjZXB0LUVuY29kaW5nOiBpZGVudGl0eQ0KSG9zdDogbWV0YWRhdGEuZ29vZ2xlLmludGVybmFsDQpVc2VyLUFnZW50OiBQeXRob24tdXJsbGliLzMuNg0KTWV0YWRhdGEtRmxhdm9yOiBHb29nbGUNCkNvbm5lY3Rpb246IGNsb3NlDQoNCg==\",\"stream\":1,\"packet\":\"QgEKAAABQgEKAAAWCABFAAAoX+pAAEAGfNMKAAAWqf6p\\/q0+AFBQUyUbj8VM+lAQczxeLQAA\",\"packet_info\":{\"linktype\":1}}",
        #                  "_serial": "0",
        #                  "_si": ["index01", "ids"],
        #                  "_subsecond": ".391761",
        #                  "_time": "2018-11-03 23:29:59.391 UTC",
        #                  "host": "t1-corp-mail-00",
        #                  "index": "ids",
        #                  "linecount": "1",
        #                  "source": "/var/log/suricata/alert-json.log",
        #                  "sourcetype": "suricata:alert",
        #                  "splunk_server": "index01"
        #                  }
        # sample_alert = {
        #     "timestamp": "2018-11-03T23:29:59.391761+0000",
        #     "flow_id": 1818990308865466,
        #     "in_iface": "ens4",
        #     "event_type": "alert",
        #     "src_ip": "10.0.0.22",
        #     "src_port": 44350,
        #     "dest_ip": "169.254.169.254",
        #     "dest_port": 80,
        #     "proto": "TCP",
        #     "tx_id": 0,
        #     "alert": {
        #         "action": "allowed",
        #         "gid": 1,
        #         "signature_id": 2013031,
        #         "rev": 6,
        #         "signature": "ET POLICY Python-urllib\\/ Suspicious User Agent",
        #         "category": "Attempted Information Leak",
        #         "severity": 2
        #     },
        #     "http": {
        #         "hostname": "metadata.google.internal",
        #         "url": "\\/computeMetadata\\/v1\\/instance\\/network-interfaces\\/?alt=json&last_etag=9db2cc14c6c04c17&recursive=True&timeout_sec=66&wait_for_change=True",
        #         "http_user_agent": "Python-urllib\\/3.6",
        #         "http_content_type": "application\\/json",
        #         "http_method": "GET",
        #         "protocol": "HTTP\\/1.1",
        #         "status": 200,
        #         "length": 319
        #     },
        #     "app_proto": "http",
        #     "payload": "R0VUIC9jb21wdXRlTWV0YWRhdGEvdjEvaW5zdGFuY2UvbmV0d29yay1pbnRlcmZhY2VzLz9hbHQ9anNvbiZsYXN0X2V0YWc9OWRiMmNjMTRjNmMwNGMxNyZyZWN1cnNpdmU9VHJ1ZSZ0aW1lb3V0X3NlYz02NiZ3YWl0X2Zvcl9jaGFuZ2U9VHJ1ZSBIVFRQLzEuMQ0KQWNjZXB0LUVuY29kaW5nOiBpZGVudGl0eQ0KSG9zdDogbWV0YWRhdGEuZ29vZ2xlLmludGVybmFsDQpVc2VyLUFnZW50OiBQeXRob24tdXJsbGliLzMuNg0KTWV0YWRhdGEtRmxhdm9yOiBHb29nbGUNCkNvbm5lY3Rpb246IGNsb3NlDQoNCg==",
        #     "stream": 1,
        #     "packet": "QgEKAAABQgEKAAAWCABFAAAoX+pAAEAGfNMKAAAWqf6p\\/q0+AFBQUyUbj8VM+lAQczxeLQAA",
        #     "packet_info": {
        #         "linktype": 1
        #     }
        # }
        alert_raw = json.loads(record['_raw'])

        if alert_raw["event_type"] != "alert":
            print(alert_raw["event_type"])
            continue

        # Trims team prefix from the host name
        host = record["host"][3:]
        timestamp = datetime.datetime.strptime(alert_raw["timestamp"], '%Y-%m-%dT%H:%M:%S.%f%z')
        time_delta_seconds = round((timestamp - previous_timestamp).total_seconds(), 2)
        previous_timestamp = timestamp

        signature = alert_raw["alert"]["signature"]
        category = alert_raw["alert"]["category"]
        # severity = alert_raw["alert"]["severity"]

        if filter_info_leak and category == "Attempted Information Leak":
            continue

        src_ip = alert_raw["src_ip"]
        src_port = alert_raw.get("src_port", None)
        dest_ip = alert_raw["dest_ip"]
        dest_port = alert_raw.get("dest_port", None)

        if src_ip == BAD_IP or dest_ip == BAD_IP or category == 'Not Suspicious Traffic':
            continue

        mcat = get_attack_stage_mapping(signature)
        result.append(
            ParsedAlert(time_delta_seconds, src_ip, src_port, dest_ip, dest_port, signature,
                        category, host, timestamp, mcat)
        )

    return result


def _remove_duplicate(alerts: List[ParsedAlert], time_delta=1.0) -> List[ParsedAlert]:
    # First alert cannot be a duplicate of the previous
    result = [alerts[0]]
    # result = []
    previous = alerts[0]

    for alert in alerts[1:]:
        # if alert.mcat == MicroAttackStage.NON_MALICIOUS and not (
        #         alert.time_delta_seconds < time_delta
        #         and is_duplicate_attack(alert, previous)):
        # if alert.mcat != MicroAttackStage.NON_MALICIOUS and not (
        #         alert.time_delta_seconds < time_delta
        #         and alert.src_ip == previous.src_ip
        #         and alert.src_port == previous.src_port
        #         and alert.dest_ip == previous.dest_ip
        #         and alert.dest_port == previous.dest_port
        #         and alert.signature == previous.signature):
        #     result.append(alert)
        if alert.mcat != MicroAttackStage.NON_MALICIOUS and not (
                alert.time_delta_seconds <= time_delta
                and is_duplicate_attack(alert, previous)):
            result.append(alert)
        previous = alert

    return result
