import numpy as np
import matplotlib.pyplot as plt

from src.Updated.mappings.mappings import micro


# TODO: re-write, or add when needed
#  Mostly kept as reference
def plot_histogram(unparse, team_labels):
    # Choice of: Suricata category usage or Micro attack stage usage?
    SURICATA_SUMMARY = False
    cats = {'A Network Trojan was detected': 0, 'Generic Protocol Command Decode': 1,
            'Attempted Denial of Service': 2, 'Attempted User Privilege Gain': 3,
            'Misc activity': 4, 'Attempted Administrator Privilege Gain': 5,
            'access to a potentially vulnerable web application': 6, 'Information Leak': 7,
            'Web Application Attack': 8, 'Successful Administrator Privilege Gain': 9,
            'Potential Corporate Privacy Violation': 10, 'Detection of a Network Scan': 11,
            'Not Suspicious Traffic': 12, 'Potentially Bad Traffic': 13,
            'Attempted Information Leak': 14}

    cols = ['b', 'r', 'g', 'c', 'm', 'y', 'k', 'olive', 'lightcoral', 'skyblue', 'mediumpurple',
            'springgreen', 'chocolate', 'cadetblue', 'lavender']

    ids = [x for x, y in micro.items()]
    vals = [y for x, y in micro.items()]
    N = -1
    t = []

    if SURICATA_SUMMARY:
        N = len(cats)
        t = [[0] * len(cats) for x in range(len(unparse))]
    else:
        N = len(vals)
        t = [[0] * len(vals) for x in range(len(unparse))]
    ind = np.arange(N)  # the x locations for the groups
    width = 0.75  # the width of the bars: can also be len(x) sequence

    for tid, team in enumerate(unparse):
        count = 0
        for ev in team:
            # if ev[9] == 999:
            #    continue
            count += 1
            # print(ev[9])
            if SURICATA_SUMMARY:
                # if cats[ev[6]] != 14:
                t[tid][cats[ev[6]]] += 1
            else:
                t[tid][ids.index(ev[9])] += 1
                # print(count)
        for i, acat in enumerate(t[tid]):
            t[tid][i] = acat / len(team)
        # print('Total percentage: '+ str(sum(t[tid])), 'Actual len: ', str(len(team)))
    p = []
    for tid, team in enumerate(unparse):
        plot = None
        if tid == 0:
            plot = plt.bar(ind, t[tid], width)
        elif tid == 1:
            plot = plt.bar(ind, t[tid], width,
                           bottom=t[tid - 1])
        else:
            inde = [x for x in range(tid)]
            bot = np.add(t[0], t[1])
            for i in inde[2:]:
                bot = np.add(bot, t[i]).tolist()
            plot = plt.bar(ind, t[tid], width,
                           bottom=bot)
        p.append(plot)

        # TODO: Decide whether to put it like this or normalize over columns
    # print(t)
    plt.ylabel('Percentage of occurance')
    plt.title('Frequency of alert category')
    if SURICATA_SUMMARY:
        plt.xticks(ind, (
            'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10', 'c11', 'c12', 'c13',
            'c14'))
    else:
        plt.xticks(ind, [x.split('.')[1] for x in vals], rotation='vertical')
    plt.tick_params(axis='x', which='major', labelsize=8)
    plt.tick_params(axis='x', which='minor', labelsize=8)
    # plt.yticks(np.arange(0, 13000, 1000))
    plt.legend([plot[0] for plot in p], team_labels)
    plt.tight_layout()
    # plt.show()
    return plt


## 14
def legend_without_duplicate_labels(ax, fontsize=10, loc='upper right'):
    handles, labels = ax.get_legend_handles_labels()
    unique = [(h, l) for i, (h, l) in enumerate(zip(handles, labels)) if l not in labels[:i]]
    unique = sorted(unique, key=lambda x: x[1])
    ax.legend(*zip(*unique), loc=loc, fontsize=fontsize)
