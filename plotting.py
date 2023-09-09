import os
import re
from collections import OrderedDict

import matplotlib.pyplot as plt
import numpy as np

from signatures.attack_stages import MicroAttackStage
from signatures.mappings import macro_inv, mcols, micro, micro2macro


def plot_alert_filtering(unfiltered_alerts, filtered_alerts):
    """
    Plots the frequency of the alerts before and after filtering next to each other, for each attack stage (mcat).

    @param unfiltered_alerts: the raw alerts before filtering (i.e. before removing duplicates)
    @param filtered_alerts: the cleaned alerts after filtering (i.e. after removing duplicates)
    """
    original, remaining = dict(), dict()
    original_mcat = [x[9] for x in unfiltered_alerts]
    for i in original_mcat:
        original[i] = original.get(i, 0) + 1

    remaining_mcat = [x[9] for x in filtered_alerts]
    for i in remaining_mcat:
        remaining[i] = remaining.get(i, 0) + 1
    if MicroAttackStage.NON_MALICIOUS.value in original:
        remaining[MicroAttackStage.NON_MALICIOUS.value] = 0  # mcat that has been filtered (non-malicious)

    # Use ordered dictionaries to make sure that the labels (categories) are aligned
    b1 = OrderedDict(sorted(original.items()))
    b2 = OrderedDict(sorted(remaining.items()))

    plt.figure(figsize=(20, 20))
    plt.gcf().subplots_adjust(bottom=0.2)  # To fit the x-labels

    # Set width and height of bar
    bar_width = 0.4
    bars1 = [x for x in b1.values()]
    bars2 = [x for x in b2.values()]

    # Set position of bar on x-axis
    r1 = np.arange(len(bars1))
    r2 = [x + bar_width for x in r1]

    # Make the plot
    plt.bar(r1, bars1, color='skyblue', width=bar_width, edgecolor='white', label='Raw')
    plt.bar(r2, bars2, color='salmon', width=bar_width, edgecolor='white', label='Cleaned')

    labels = [micro[x].split('.')[1] for x in b1.keys()]

    # Add xticks in the middle of the group bars
    plt.ylabel('Frequency', fontweight='bold', fontsize='20')
    plt.xlabel('Alert categories', fontweight='bold', fontsize='20')
    plt.xticks([(x + bar_width / 2) for x in r1], labels, fontsize='10', rotation='vertical')
    plt.yticks(fontsize='20')
    plt.title('High-frequency Alert Filtering', fontweight='bold', fontsize='20')

    # Create legend & show graphic
    plt.legend(prop={'size': 20})
    plt.show()


def plot_histogram(team_alerts, team_labels, experiment_name, suricata_summary=False):
    """
    Plots for each team, how many categories are consumed.

    @param team_alerts: the alerts grouped per team after filtering (i.e. after removing duplicates)
    @param team_labels: the labels of the teams (which correspond to the file name without the '.json' extension)
    @param experiment_name: the name of the experiment
    @param suricata_summary: whether to use suricata summary or Micro Attack Stage
    """
    # Choice of: Suricata category usage or Micro attack stage usage? (has to be updated when used)
    suricata_categories = {
        'A Network Trojan was detected': 0, 'Generic Protocol Command Decode': 1, 'Attempted Denial of Service': 2,
        'Attempted User Privilege Gain': 3, 'Misc activity': 4, 'Attempted Administrator Privilege Gain': 5,
        'access to a potentially vulnerable web application': 6, 'Information Leak': 7, 'Web Application Attack': 8,
        'Successful Administrator Privilege Gain': 9, 'Potential Corporate Privacy Violation': 10,
        'Detection of a Network Scan': 11, 'Not Suspicious Traffic': 12, 'Potentially Bad Traffic': 13,
        'Attempted Information Leak': 14
    }

    micro_attack_stages_codes = [x for x, _ in micro.items()]
    micro_attack_stages = [y for _, y in micro.items()]

    if suricata_summary:
        num_categories = len(suricata_categories)
        percentages = [[0 * num_categories] for _ in range(len(team_alerts))]
    else:
        num_categories = len(micro_attack_stages)
        percentages = [[0] * num_categories for _ in range(len(team_alerts))]
    indices = np.arange(num_categories)    # The x locations for the groups
    bar_width = 0.75       # The width of the bars: can also be len(x) sequence

    for tid, team in enumerate(team_alerts):
        for alert in team:
            if suricata_summary:
                percentages[tid][suricata_categories[alert[6]]] += 1
            else:
                percentages[tid][micro_attack_stages_codes.index(alert[9])] += 1
        for i, acat in enumerate(percentages[tid]):
            percentages[tid][i] = acat / len(team)
    plots = []
    for tid, team in enumerate(team_alerts):
        if tid == 0:
            plot = plt.bar(indices, percentages[tid], bar_width)
        elif tid == 1:
            plot = plt.bar(indices, percentages[tid], bar_width, bottom=percentages[tid - 1])
        else:
            index = [x for x in range(tid)]
            bottom = np.add(percentages[0], percentages[1])
            for i in index[2:]:
                bottom = np.add(bottom, percentages[i]).tolist()
            plot = plt.bar(indices, percentages[tid], bar_width, bottom=bottom)
        plots.append(plot)

        # TODO: Decide whether to put it like this or normalize over columns
    plt.ylabel('Percentage of occurrence')
    plt.title('Frequency of alert category')
    if suricata_summary:
        plt.xticks(indices, ['c' + str(i) for i in range(15)])  # 14 columns
    else:
        plt.xticks(indices, [x.split('.')[1] for x in micro_attack_stages], rotation='vertical')
    plt.tick_params(axis='x', which='major', labelsize=8)
    plt.tick_params(axis='x', which='minor', labelsize=8)
    # plt.yticks(np.arange(0, 13000, 1000))
    plt.legend([plot[0] for plot in plots], team_labels)
    plt.tight_layout()
    plt.savefig('data_histogram-' + experiment_name + '.png')
    # plt.show()


def plot_episodes(frequencies, episodes, mcat):
    """
    Plot the slopes based on the time, for a given (hyper)alert sequence (for an attacker-victim pair and mcat).

    @param frequencies: the frequencies of the corresponding alert windows
    @param episodes: the episodes for the given (hyper)alert sequence
    @param mcat: the corresponding Micro Attack Stage
    """
    cap = max(frequencies) + 1

    plt.figure()
    plt.title(mcat)
    plt.xlabel('Time ->')
    plt.ylabel('Slope')
    plt.plot(frequencies, 'gray')
    for ep in episodes:
        xax_start = [ep[0]] * cap
        xax_end = [ep[1]] * cap
        yax = list(range(cap))

        plt.plot(xax_start, yax, 'g', linestyle=(0, (5, 10)))
        plt.plot(xax_end, yax, 'r', linestyle=(0, (5, 10)))

    plt.show()


def _legend_without_duplicate_labels(ax, fontsize=10, loc='upper right'):
    """
    Creates a legend without duplicate labels.

    @param ax: the axis for which the legend has to be created
    @param fontsize: the size of the font
    @param loc: the location of the legend
    """
    handles, labels = ax.get_legend_handles_labels()
    unique = [(h, l) for i, (h, l) in enumerate(zip(handles, labels)) if l not in labels[:i]]
    unique = sorted(unique, key=lambda x: x[1])
    ax.legend(*zip(*unique), loc=loc, fontsize=fontsize)


def plot_alert_volume_per_episode(tid, attacker_victim, host_episodes, mcats):
    """
    Plots the alert volume per episode for the episodes of the given attacker-victim pair and the given mcat.

    @param tid: the ID of the team
    @param attacker_victim: the attacker-victim pair to create plots for
    @param host_episodes: episodes for a given attacker-victim pair and mcat
    @param mcats: a list with the Micro Attack Stages
    """
    plt.figure(figsize=(10, 10))
    ax = plt.gca()
    plt.title('Micro attack episodes | Team: ' + str(tid) + ' | Host: ' + '->'.join(attacker_victim))
    plt.xlabel('Time Window (sec)')
    plt.ylabel('Micro attack stages')
    # NOTE: Line thicknesses are on per-host basis
    tmax = max([epi[4] for epi in host_episodes])
    tmin = min([epi[4] for epi in host_episodes])
    for idx, ep in enumerate(host_episodes):
        xax = list(np.arange(ep[0], ep[1] + 1))
        yax = [mcats.index(ep[2])] * len(xax)
        thickness = ep[4]
        lsize = ((thickness - tmin) / (tmax - tmin)) * (5 - 0.5) + 0.5 if (tmax - tmin) != 0.0 else 0.5
        # lsize = np.log(thickness) + 1 TODO: Either take log or normalize between [0.5 5]
        msize = (lsize * 2) + 1
        ax.plot(xax, yax, color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], linewidth=lsize)
        ax.plot(ep[0], mcats.index(ep[2]), color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.', linewidth=0,
                markersize=msize, label=micro2macro[micro[ep[2]]])
        ax.plot(ep[1], mcats.index(ep[2]), color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.', linewidth=0,
                markersize=msize)
        plt.yticks(range(len(mcats)), [x.split('.')[1] for x in micro.values()], rotation=0)
    _legend_without_duplicate_labels(ax)
    plt.grid(True, alpha=0.4)

    # plt.tight_layout()
    # plt.savefig('Pres-Micro-attack-episodes-Team'+str(tid) +'-Connection'+ attacker[0]+'--'+attacker[1]+'.png')
    plt.show()


def plot_state_groups(state_sequences, data_file):
    """
    Creates and plots the stage clusters (aka state groups), based on Macro Attack Stages.

    @param state_sequences: the previously created state sequences (per attacker-victim pair)
    @param data_file: the name of the file with the traces (will be a part of the name of the output file)
    @return: the created state groups (i.e. MacroAttackStage -> <set_of_stateIDs>)
    """
    state_groups = dict()
    all_states = set()
    gcols = ['lemonchiffon', 'gold', 'khaki', 'darkkhaki', 'beige', 'goldenrod',
             'wheat', 'papayawhip', 'orange', 'oldlace', 'bisque']
    for _, episodes in state_sequences.items():
        states = [(epi[2], epi[3]) for epi in episodes]
        all_states.update([epi[3] for epi in episodes])

        for i, state in enumerate(states):
            macro = micro2macro[micro[state[0]]].split('.')[1]
            if state[1] == -1 or state[1] == 0:  # Skip the root node and nodes with ID -1
                continue
            if macro not in state_groups.keys():
                state_groups[macro] = set()
            state_groups[macro].add(state[1])

    with open(data_file + ".ff.final.dot", 'r') as model_file:
        model_lines = model_file.readlines()
    written = []
    outlines = ['digraph modifiedDFA {\n']
    for gid, (group, states) in enumerate(state_groups.items()):
        print(group)
        outlines.append('subgraph cluster_' + group + ' {\n')
        outlines.append('style=filled;\n')
        outlines.append('color=' + gcols[gid] + ';\n')
        outlines.append('label = "' + group + '";\n')
        for i, line in enumerate(model_lines):
            node_line = re.match('\\D+(\\d+)\\s\\[\\slabel="\\d.*', line)
            if node_line:
                node = int(node_line.group(1))
                if node in states:
                    c = i
                    while '];' not in model_lines[c]:
                        outlines.append(model_lines[c])
                        written.append(c)
                        c += 1
                    outlines.append(model_lines[c])
                    written.append(c)
                elif node not in all_states and group == 'ACTIVE_RECON':
                    if node != 0:
                        c = i
                        while '];' not in model_lines[c]:
                            outlines.append(model_lines[c])
                            written.append(c)
                            c += 1
                        outlines.append(model_lines[c])
                        written.append(c)
                        state_groups['ACTIVE_RECON'].add(node)
                    print('ERROR: manually handled', node, ' in ACTIVE_RECON')  # TODO: include edges or not?
            '''edge_line = re.match('\\D+(\\d+)\\s->\\s(\\d+)\\s\\[label=.*', line)  # 0 -> 1 [label=
            if edge_line:
                node = int(edge_line.group(1))
                if node in states:
                    c = i
                    while '];' not in model_lines[c]:
                        outlines.append(model_lines[c])
                        written.append(c)
                        c += 1
                    outlines.append(model_lines[c])
                    written.append(c)'''
        outlines.append('}\n')

    for i, line in enumerate(model_lines):
        if i < 2:
            continue
        if i not in written:
            outlines.append(line)

    filename = 'spdfa-clustered-' + data_file + '-dfa'
    with open(filename + '.dot', 'w') as outfile:
        for line in outlines:
            outfile.write(line)

    os.system("dot -Tpng " + filename + ".dot -o " + filename + ".png")
    return state_groups
