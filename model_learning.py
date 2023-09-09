import json
import re
import subprocess
from collections import defaultdict

from signatures.mappings import small_mapping, rev_smallmapping


def _most_frequent(serv):
    """
    Gets the most frequently occurring service in a list of services, which is further used in attack graphs.
    As a tie-breaker, if an 'unknown' service has the same count as a specific service, the latter is explicitly chosen.

    @param serv: a list of services
    @return: the most frequently occurring service (the most targeted service)
    """
    max_frequency = 0
    most_frequent_service = None
    count_unknown = 0
    for s in serv:
        frequency = serv.count(s)
        # Count the frequency of 'unknown' to break a tie against it
        if s == 'unknown':
            count_unknown = frequency
            continue
        if frequency > max_frequency:
            most_frequent_service = s
            max_frequency = frequency
    return most_frequent_service if max_frequency >= count_unknown else 'unknown'


# Step 4.2: Generate traces for FlexFringe (27 Aug 2020)
def generate_traces(subsequences, datafile):
    """
    Generates the episode traces to pass to FlexFringe. An episode trace is a (reversed) sequence of `mcat|mserv`.

    @param subsequences: the episode subsequences per attacker-victim pair
    @param datafile: the file where the traces have to be written to
    @return: the FlexFringe traces (to be reused in the `encode_sequences` function)
    """
    num_traces = 0
    unique_symbols = set()  # FlexFringe treats the (mcat,mserv) pairs as symbols of the alphabet

    flexfringe_traces = []
    for i, episodes in enumerate(subsequences.values()):
        if len(episodes) < 3:  # Discard subsequences of length < 3 (can be commented out, also in make_state_sequences)
            continue
        num_traces += 1
        mcats = [x[2] for x in episodes]
        num_services = [len(set((x[6]))) for x in episodes]
        max_services = [_most_frequent(x[6]) for x in episodes]

        # symbols = [str(mcat) + ":" + str(num_serv) + "," + str(mserv) for (mcat, num_serv, mserv) in zip(mcats, num_services, max_services)]  # Multivariate case (TODO: has to be fixed if used)
        symbols = [small_mapping[mcat] + "|" + mserv for mcat, mserv in zip(mcats, max_services)]
        unique_symbols.update(symbols)
        symbols.reverse()  # Reverse traces to accentuate high-severity episodes (to create an S-PDFA)
        trace = '1' + " " + str(len(mcats)) + ' ' + ' '.join(symbols) + '\n'
        flexfringe_traces.append(trace)

    with open(datafile, 'w') as f:
        f.write(str(num_traces) + ' ' + str(len(unique_symbols)) + '\n')
        for trace in flexfringe_traces:
            f.write(trace)
    print('\n# episode traces:', len(flexfringe_traces))
    return flexfringe_traces


# Step 5: Learn the model (2 sept 2020)
def flexfringe(*args, **kwargs):
    """
    Acts as a wrapper to call the FlexFringe binary to create an S-PDFA model.

    @param args: the input file with the episode traces (position 0)
    @param kwargs: the list of key=value arguments to pass as command line arguments
    """

    command = []
    if len(kwargs) == 1:
        command = ["--help"]
    for key in kwargs:
        command += ["--" + key + "=" + kwargs[key]]

    result = subprocess.run(["FlexFringe/flexfringe"] + command + [args[0]], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    print(result.returncode, result.stdout, result.stderr)


# Step 6.1: Load the resulting model
def load_model(model_file):
    """
    Loads the resulting S-PDFA model from a json file created by FlexFringe.
    First this method is called on the core model, then on the sinks model.

    @param model_file: the path to the json file with the model
    @return: the resulting S-PDFA model (in a dictionary format)
    """

    # Because users can provide unescaped new lines breaking json conventions
    #   in the labels, we are removing them from the label fields
    with open(model_file) as fh:
        model_data = fh.read()
        model_data = re.sub(r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', model_data)

    model_data = model_data.replace('\n', '').replace(',,', ',')
    model_data = re.sub(',+', ',', model_data)
    machine = json.loads(model_data)

    dfa = defaultdict(lambda: defaultdict(str))
    for edge in machine["edges"]:
        dfa[edge["source"]][edge["name"]] = edge["target"]

    # Even though the properties might not be needed, the node has to be present in the dictionary (for sinks)
    for entry in machine["nodes"]:
        dfa[str(entry['id'])]["isred"] = entry['isred']
        dfa[str(entry['id'])]["isblue"] = entry['isblue']
        dfa[str(entry['id'])]["issink"] = entry['issink']

    return dfa


def traverse(dfa, sinks, sequence):
    """
    Traverses the given S-PDFA model with a trace string to collect the state IDs.

    @param dfa: the loaded main model
    @param sinks: the loaded sinks model
    @param sequence: the space-separated string to traverse the S-PDFA and get the state IDs
    @return: the list of state IDs and the found severe sinks (medium- and high-severity sinks only)
    """
    sev_sinks = set()
    state = "0"
    state_list = ["0"]
    for event in sequence.split(" "):
        sym = event.split(":")[0]  # This is needed for the multivariate case in `generate_traces` function
        sev = rev_smallmapping[sym.split('|')[0]]

        if state in dfa and sym in dfa[state]:  # Use the main model if possible, otherwise use the model with the sinks
            state = dfa[state][sym]
            state_list.append(state)
        else:
            if state in sinks and sym in sinks[state]:
                state = sinks[state][sym]
            else:
                state = '-1'  # With `printblue = 1` in spdfa-config.ini this should not happen

            state_to_save = state if len(str(sev)) >= 2 else '-1'  # Discard IDs from low-severity sinks
            state_list.append(state_to_save)

        if state in sinks and len(str(sev)) >= 2:  # Save med- and high-sev sinks (might be defined in the main model)
            sev_sinks.add(state)

    return state_list, sev_sinks


# Step 6.2: Encode traces (include state IDs to mcat|mserv)
def encode_sequences(dfa, sinks, flexfringe_traces):
    """
    Encodes the episode traces into state traces, i.e. gathers the state IDs.

    @param dfa: the loaded main model
    @param sinks: the loaded sinks model
    @param flexfringe_traces: the traces that were passed to FlexFringe in the `generate_traces` function
    @return: the state traces, the found medium- and high-severity states, and the medium- and high-severity sinks
    """
    traces_in_sinks, total_traces = 0, 0
    state_traces = dict()
    med_sev_states, high_sev_states, sev_sinks = set(), set(), set()
    for i, sample in enumerate(flexfringe_traces):
        sample = ' '.join(sample.strip('\n').split(' ')[2:])  # Remove the first number and len(mcats)
        state_list, _sev_sinks = traverse(dfa, sinks, sample)
        state_list = state_list[1:]  # Remove the root node (with state ID 0)
        state_traces[i] = state_list

        total_traces += len(state_list)
        traces_in_sinks += state_list.count('-1')

        assert (len(sample.split(' ')) == len(state_traces[i]))

        sample = sample.split(' ')
        med_sev = [int(state) for sym, state in zip(sample, state_list) if
                   len(str(rev_smallmapping[sym.split('|')[0]])) == 2]
        med_sev_states.update(med_sev)
        high_sev = [int(state) for sym, state in zip(sample, state_list) if
                    len(str(rev_smallmapping[sym.split('|')[0]])) == 3]
        high_sev_states.update(high_sev)
        sev_sinks.update(_sev_sinks)

    print('Traces in sinks:', traces_in_sinks, 'Total traces:', total_traces, 'Percentage:',
          100 * (traces_in_sinks / float(total_traces)))
    print('Total medium-severity states:', len(med_sev_states))
    print('Total high-severity states:', len(high_sev_states))
    print('Total severe sinks:', len(sev_sinks))
    return state_traces, med_sev_states, high_sev_states, sev_sinks


# Step 6.3: Create state sequences
def make_state_sequences(episode_subsequences, state_traces):
    """
    Creates state sequences, i.e. collects the sub-behaviors back into a single sequence, augmenting with state IDs.

    @param episode_subsequences: the previously created episode subsequences
    @param state_traces: the previously created state traces (the lists of state IDs)
    @return: state sequences per each attacker-victim pair
    """
    state_sequences = dict()
    counter = -1
    for tid, (attack, episode_subsequence) in enumerate(episode_subsequences.items()):

        if len(episode_subsequence) < 3:  # Discard subsequences of length < 3 (as in generate_traces)
            continue
        counter += 1

        trace = [int(state) for state in state_traces[counter]]
        max_services = [_most_frequent(epi[6]) for epi in episode_subsequence]

        trace = trace[::-1]  # Reverse the trace from the S-PDFA back

        # start_time, end_time, mcat, state_ID, mserv, list of unique signatures, (1st and last timestamp)
        state_subsequence = [(epi[0], epi[1], epi[2], trace[i], max_services[i], epi[7], epi[8])
                             for i, epi in enumerate(episode_subsequence)]

        parts = attack.split('->')
        attacker_victim = parts[0] + '->' + parts[1].split('-')[0]  # Remove the subsequence number (if present)

        if attacker_victim not in state_sequences.keys():
            state_sequences[attacker_victim] = []
        state_sequences[attacker_victim].extend(state_subsequence)
        state_sequences[attacker_victim].sort(key=lambda epi: epi[0])  # Sort in place based on starting times

    return state_sequences


def group_episodes_per_av(state_sequences):
    """
    Groups the episodes (state sequences) per (team, victim) pair and per (team, attacker) pair (separately).

    @param state_sequences: the previously created state sequences per attacker-victim pair
    @return: episodes per (team, victim) pair, episodes per (team, attacker) pair
    """
    # Experiment: attack graph for one victim w.r.t time
    victim_episodes = dict()  # Episodes per (team, victim)
    for attack, episodes in state_sequences.items():
        team = attack.split('-')[0]
        victim = attack.split('->')[1]
        team_victim = team + '-' + victim
        if team_victim not in victim_episodes.keys():
            victim_episodes[team_victim] = []
        victim_episodes[team_victim].extend(episodes)
        victim_episodes[team_victim] = sorted(victim_episodes[team_victim], key=lambda epi: epi[0])  # By start time
    # Sort by start time across all
    victim_episodes = {k: v for k, v in sorted(victim_episodes.items(), key=lambda kv: len([epi[0] for epi in kv[1]]))}
    print('Victims hosts: ', set([team_victim.split('-')[-1] for team_victim in victim_episodes.keys()]))

    attacker_episodes = dict()  # Episodes per (team, attacker)
    for attack, episodes in state_sequences.items():
        team = attack.split('-')[0]
        attacker = (attack.split('->')[0]).split('-')[1]
        team_attacker = team + '-' + attacker
        if team_attacker not in attacker_episodes.keys():
            attacker_episodes[team_attacker] = []
        attacker_episodes[team_attacker].extend(episodes)
        attacker_episodes[team_attacker] = sorted(attacker_episodes[team_attacker], key=lambda epi: epi[0])
    print('Attacker hosts: ', set([team_attacker.split('-')[1] for team_attacker in attacker_episodes.keys()]))

    return victim_episodes, attacker_episodes
