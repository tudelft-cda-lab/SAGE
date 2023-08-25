import argparse
import csv
import datetime
import glob
import json
import os
import re
import sys

import requests

from ag_generation import make_attack_graphs
from episode_sequence_generation import aggregate_into_episodes, host_episode_sequences, break_into_subbehaviors
from model_learning import generate_traces, flexfringe, load_model, encode_sequences, make_state_sequences
from plotting import plot_alert_filtering, plot_histogram, plot_state_groups
from signatures.attack_stages import MicroAttackStage
from signatures.mappings import micro_inv
from signatures.alert_signatures import usual_mapping, unknown_mapping, ccdc_combined, attack_stage_mapping


IANA_CSV_FILE = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_NUM_RETRIES = 5
SAVE_AG = True


def _get_attack_stage_mapping(signature):
    result = MicroAttackStage.NON_MALICIOUS
    if signature in usual_mapping.keys():
        result = usual_mapping[signature]
    elif signature in unknown_mapping.keys():
        result = unknown_mapping[signature]
    elif signature in ccdc_combined.keys():
        result = ccdc_combined[signature]
    else:
        for k, v in attack_stage_mapping.items():
            if signature in v:
                result = k
                break
    return micro_inv[str(result)]

 
# Step 0: Download the IANA port-service mapping
def load_iana_mapping():
    # Perform the first request and in case of a failure retry the specified number of times
    for attempt in range(IANA_NUM_RETRIES + 1):
        response = requests.get(IANA_CSV_FILE)
        if response.ok:
            content = response.content.decode("utf-8")
            break
        elif attempt < IANA_NUM_RETRIES:
            print('Could not download IANA ports. Retrying...')
        else:
            raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

    # Drop headers (service name, port, protocol, description, ...)
    next(table)

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
                    "name": row[0] if row[0] else "unknown",
                    "description": row[3] if row[3] else "---",
                }
    return ports


def _readfile(fname):
    with open(fname, 'r') as f:
        unparsed_data = json.load(f)
        
    unparsed_data = unparsed_data[::-1]
    return unparsed_data


# Step 1.1: Parse the input alerts
def _parse(unparsed_data, filter_alerts=False):
    bad_ip = '169.254.169.254'
    parsed_data = []

    prev = -1
    for d in unparsed_data:
        if 'result' in d and '_raw' in d['result']:
            raw = json.loads(d['result']['_raw'])
        elif '_raw' in d:
            raw = json.loads(d['_raw'])
        else:
            raw = d

        if raw['event_type'] != 'alert':
            continue

        if 'host' in raw:
            host = raw['host']
        elif 'host' in d:
            host = d['host'][3:]
        else:
            host = 'dummy'

        dt = datetime.datetime.strptime(raw['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')  # 2018-11-03T23:16:09.148520+0000
        diff_dt = 0.0 if prev == -1 else round((dt - prev).total_seconds(), 2)
        prev = dt

        sig = raw['alert']['signature']
        cat = raw['alert']['category']

        # Filter out the alert that occurs way too often
        if cat == 'Attempted Information Leak' and filter_alerts:
            continue

        src_ip = raw['src_ip']
        src_port = None if 'src_port' not in raw.keys() else raw['src_port']
        dst_ip = raw['dest_ip']
        dst_port = None if 'dest_port' not in raw.keys() else raw['dest_port']

        # Filter out mistaken alerts / uninteresting alerts
        if src_ip == bad_ip or dst_ip == bad_ip or cat == 'Not Suspicious Traffic':
            continue

        mcat = _get_attack_stage_mapping(sig)
        parsed_data.append((diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, dt, mcat))

    print('Reading # alerts: ', len(parsed_data))
    parsed_data = sorted(parsed_data, key=lambda al: al[8])  # Sort alerts into ascending order
    return parsed_data


# Step 1.2: Remove duplicate alerts (defined by the alert_filtering_window parameter)
def _remove_duplicates(unfiltered_alerts, plot=False, gap=1.0):
    filtered_alerts = [unfiltered_alerts[x] for x in range(1, len(unfiltered_alerts))
                       if unfiltered_alerts[x][9] != MicroAttackStage.NON_MALICIOUS.value  # Skip non-malicious alerts
                       and not (unfiltered_alerts[x][0] <= gap  # Diff from previous alert is less than gap sec
                                and unfiltered_alerts[x][1] == unfiltered_alerts[x - 1][1]  # Same srcIP
                                and unfiltered_alerts[x][3] == unfiltered_alerts[x - 1][3]  # Same destIP
                                and unfiltered_alerts[x][5] == unfiltered_alerts[x - 1][5]  # Same suricata category
                                and unfiltered_alerts[x][2] == unfiltered_alerts[x - 1][2]  # Same srcPort
                                and unfiltered_alerts[x][4] == unfiltered_alerts[x - 1][4])]  # Same destPort
    if plot:
        plot_alert_filtering(unfiltered_alerts, filtered_alerts)

    print('Filtered # alerts (remaining):', len(filtered_alerts))
    return filtered_alerts


# Step 1: Read the input alerts
def load_data(path_to_alerts, filtering_window, start, end):
    _team_alerts = []
    _team_labels = []
    _team_start_times = []  # Record the first alert just to get the real elapsed time (if the user filters (s,e) range)
    files = glob.glob(path_to_alerts + "/*.json")
    print('About to read json files...')
    if len(files) < 1:
        print('No alert files found.')
        sys.exit()
    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)
        _team_labels.append(name)

        parsed_alerts = _parse(_readfile(f))
        parsed_alerts = _remove_duplicates(parsed_alerts, gap=filtering_window)

        # EXP: Limit alerts by timing is better than limiting volume because each team is on a different scale.
        # 50% alerts for one team end at a diff time than for others
        end_time_limit = 3600 * end       # Which hour to end at?
        start_time_limit = 3600 * start   # Which hour to start from?

        first_ts = parsed_alerts[0][8]
        _team_start_times.append(first_ts)

        filtered_alerts = [x for x in parsed_alerts if (((x[8] - first_ts).total_seconds() <= end_time_limit)
                                                        and ((x[8] - first_ts).total_seconds() >= start_time_limit))]
        _team_alerts.append(filtered_alerts)

    return _team_alerts, _team_labels, _team_start_times


# Reorganise alerts for each attacker per team
def group_alerts_per_team(alerts, port_mapping):
    _team_data = dict()
    for tid, team in enumerate(alerts):
        host_alerts = dict()  # (attacker, victim) -> alerts

        for alert in team:
            # Alert format: (diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, ts, mcat)
            src_ip, dst_ip, signature, ts, mcat = alert[1], alert[3], alert[5], alert[8], alert[9]
            dst_port = alert[4] if alert[4] is not None else 65000

            # Say 'unknown' if the port cannot be resolved
            if dst_port not in port_mapping.keys() or port_mapping[dst_port] == 'unknown':
                dst_port = 'unknown'
            else:
                dst_port = port_mapping[dst_port]['name']

            # TODO: add the check for 10.0.254 in src_ip or in dst_ip - if not, then discard
            # TODO: If present in src_ip, then add (src_ip, dst_ip). If in dst_ip, then add (dst_ip, src_ip)
            # TODO: for the future, we might want to address internal paths
            if (src_ip, dst_ip) not in host_alerts.keys() and (dst_ip, src_ip) not in host_alerts.keys():
                host_alerts[(src_ip, dst_ip)] = []

            if (src_ip, dst_ip) in host_alerts.keys():  # TODO: remove the redundant host names
                host_alerts[(src_ip, dst_ip)].append((dst_ip, mcat, ts, dst_port, signature))
            else:
                host_alerts[(dst_ip, src_ip)].append((src_ip, mcat, ts, dst_port, signature))

        _team_data[tid] = host_alerts.items()
    return _team_data


# ----- MAIN ------
parser = argparse.ArgumentParser(description='SAGE: Intrusion Alert-Driven Attack Graph Extractor.')
parser.add_argument('path_to_json_files', type=str, help='Directory containing intrusion alerts in json format. sample-input.json provides an example of the accepted file format')
parser.add_argument('experiment_name', type=str, help='Custom name for all artefacts')
parser.add_argument('-t', type=float, required=False, default=1.0, help='Time window in which duplicate alerts are discarded (default: 1.0 sec)')
parser.add_argument('-w', type=int, required=False, default=150, help='Aggregate alerts occuring in this window as one episode (default: 150 sec)')
parser.add_argument('--timerange', type=int, nargs=2, required=False, default=[0, 100], help='Filtering alerts. Only parsing from and to the specified hours, relative to the start of the alert capture (default: (0, 100))')
parser.add_argument('--dataset', required=False, type=str, choices=['cptc', 'other'], default='other', help='The name of the dataset with the alerts (default: other)')
parser.add_argument('--keep-files', action='store_true', help='Do not delete the dot files after the program ends')
args = parser.parse_args()

path_to_json_files = args.path_to_json_files
experiment_name = args.experiment_name
alert_filtering_window = args.t
alert_aggr_window = args.w
start_hour, end_hour = args.timerange
dataset_name = args.dataset
delete_files = not args.keep_files

path_to_ini = "FlexFringe/ini/spdfa-config.ini"

path_to_traces = experiment_name + '.txt'
ag_directory = experiment_name + 'AGs'

print('------ Downloading the IANA port-service mapping ------')
port_services = load_iana_mapping()

print('------ Reading alerts ------')
team_alerts, team_labels, team_start_times = load_data(path_to_json_files, alert_filtering_window, start_hour, end_hour)
plot_histogram(team_alerts, team_labels, experiment_name)
team_data = group_alerts_per_team(team_alerts, port_services)

print('------ Converting to episodes ------')
team_episodes, _ = aggregate_into_episodes(team_data, team_start_times, step=alert_aggr_window)

print('\n------ Converting to episode sequences ------')
host_data = host_episode_sequences(team_episodes)

print('------ Breaking into sub-sequences and generating traces ------')
episode_subsequences = break_into_subbehaviors(host_data)
episode_traces = generate_traces(episode_subsequences, path_to_traces)


print('------ Learning S-PDFA ------')
flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")

os.system("dot -Tpng " + path_to_traces + ".ff.final.dot -o " + path_to_traces + ".png")

print('------ !! Special: Fixing syntax error in main model and sink files ------')
print('--- Sinks')
with open(path_to_traces + ".ff.finalsinks.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.finalsinks.json", 'w') as file:
        file.write(filedata)

print('--- Main')
with open(path_to_traces + ".ff.final.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.final.json", 'w') as file:
        file.write(filedata)

print('------ Loading and traversing S-PDFA ------')
main_model = load_model(path_to_traces + ".ff.final.json")
sinks_model = load_model(path_to_traces + ".ff.finalsinks.json")

print('------ Encoding traces into state sequences ------')
state_traces, med_sev_states, high_sev_states, severe_sinks = encode_sequences(main_model, sinks_model, episode_traces)
state_sequences = make_state_sequences(episode_subsequences, state_traces)

# print('------ Clustering state groups ------')
# state_groups = plot_state_groups(state_sequences, path_to_traces)

print('------ Making alert-driven AGs ------')
make_attack_graphs(state_sequences, severe_sinks, path_to_traces, ag_directory, SAVE_AG)

if delete_files:
    print('Deleting extra files')
    os.system("rm " + path_to_traces + ".ff.final.dot")
    os.system("rm " + path_to_traces + ".ff.final.json")
    os.system("rm " + path_to_traces + ".ff.finalsinks.json")
    os.system("rm " + path_to_traces + ".ff.finalsinks.dot")
    os.system("rm " + path_to_traces + ".ff.init.dot")
    os.system("rm " + path_to_traces + ".ff.init.json")
    os.system("rm " + path_to_traces + ".ff.initsinks.dot")
    os.system("rm " + path_to_traces + ".ff.initsinks.json")
    # os.system("rm " + "spdfa-clustered-" + path_to_traces + "-dfa.dot")  # Comment out if this file is created
    os.system("rm " + ag_directory + "/*.dot")

print('\n------- FIN -------')
# ----- END MAIN ------
