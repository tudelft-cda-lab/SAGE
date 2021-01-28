import datetime
import json
import glob
import os

from src.mappings import micro, get_attack_stage_mapping


def readfile(fname):
    unparsed_data = None
    with open(fname, 'r') as f:
        unparsed_data = json.load(f)
    unparsed_data = unparsed_data[::-1]
    # print('# events: ', len(unparsed_data))
    # print(unparsed_data[0])
    return unparsed_data


# cats = dict()
# ips = dict()
# hosts = dict()
# h_trig = []

def parse(unparsed_data, alert_labels=None, slim=False, YEAR='2018'):
    if alert_labels is None:
        alert_labels = list()
    FILTER = False
    badIP = '169.254.169.254'
    __cats = set()
    __ips = set()
    __hosts = set()
    __sev = set()
    data = []
    connections = dict()

    prev = -1
    for id, d in enumerate(unparsed_data):
        # print(d)

        raw = ''
        if YEAR == '2017':
            raw = json.loads(d['result']['_raw'])
        elif YEAR == '2018':
            raw = json.loads(d['_raw'])
        else:
            raw = d
        if raw['event_type'] != 'alert':
            continue
        # app_proto = raw['app_proto']
        host = ''
        if YEAR == '2017':
            try:
                host = raw['host']
            except:
                host = 'dummy'
        elif YEAR == '2018':
            host = d['host'][3:]
        else:
            host = 'dummy'
        # print(host)
        ts = raw['timestamp']
        dt = datetime.datetime.strptime(ts,
                                        '%Y-%m-%dT%H:%M:%S.%f%z')  # 2018-11-03T23:16:09.148520+0000
        DIFF = 0.0 if prev == -1 else round((dt - prev).total_seconds(), 2)
        prev = dt

        sig = raw['alert']['signature']
        cat = raw['alert']['category']

        severity = raw['alert']['severity']

        if cat == 'Attempted Information Leak' and FILTER:
            continue
        srcip = raw['src_ip']
        srcport = None if 'src_port' not in raw.keys() else raw['src_port']
        dstip = raw['dest_ip']
        dstport = None if 'dest_port' not in raw.keys() else raw['dest_port']

        # Filtering out mistaken alerts / uninteresting alerts
        if srcip == badIP or dstip == badIP or cat == 'Not Suspicious Traffic':
            continue

        if not slim:
            mcat = get_attack_stage_mapping(sig)
            data.append((DIFF, srcip, srcport, dstip, dstport, sig, cat, host, dt, mcat))
        else:
            data.append((DIFF, srcip, srcport, dstip, dstport, sig, cat, host, dt))

        # host_ip.append((host, srcip, dstip))

        __cats.add(cat)
        __ips.add(srcip)
        __ips.add(dstip)
        __hosts.add(host)
        __sev.add(severity)

    # _cats = [(id,c) for (id,c) in enumerate(__cats)]
    # for (i,c) in _cats:
    #     if c not in cats.keys():
    #         cats[c] = 0 if len(cats.values())==0 else max(cats.values())+1
    # _ips = [(id,ip) for (id,ip) in enumerate(__ips)]
    # for (i,ip) in _ips:
    #     if ip not in ips.keys():
    #         ips[ip] = 0 if len(ips.values())==0 else max(ips.values())+1
    # _hosts = [(id,h) for (id,h) in enumerate(__hosts)]
    # for (i,h) in _hosts:
    #     if h not in hosts.keys():
    #         hosts[h] = 0 if len(hosts.values())==0 else max(hosts.values())+1

    # print(cats)
    # print(len(cats))
    # print(data[0][1], data[0][3])
    # print(data[1][1], data[1][3])
    print('Reading # alerts: ', len(data))

    if slim:
        print(len(data), len(alert_labels))
        j = 0
        for i, al in enumerate(alert_labels):
            spl = al.split(',')
            source = spl[0]
            dest = spl[1]
            mcat = int(spl[-1][:-1])
            cat = spl[2]

            if source == badIP or dest == badIP or cat == 'Not Suspicious Traffic':
                continue
            if spl[2] == 'Attempted Information Leak' and FILTER:
                continue

            if source == data[j][1] and dest == data[j][3]:
                data[j] += (mcat,)
            j += 1
    return data


def removeDup(unparse, plot=False, t=1.0):
    # if plot:
    #     orig, removed = dict(), dict()
    #
    #     for _unparse in unparse:
    #
    #         li = [x[9] for x in _unparse]
    #
    #         for i in li:
    #             orig[i] = orig.get(i, 0) + 1
    #         print(orig.keys())
    #
    #         li = [_unparse[x] for x in range(1, len(_unparse)) if _unparse[x][9] != 999 and not (
    #                     _unparse[x][0] <= t  # Diff from previous alert is less than x sec
    #                     and _unparse[x][1] == _unparse[x - 1][1]  # same srcIP
    #                     and _unparse[x][3] == _unparse[x - 1][3]  # same destIP
    #                     and _unparse[x][5] == _unparse[x - 1][5]  # same suricata category
    #                     and _unparse[x][2] == _unparse[x - 1][2]  # same srcPort
    #                     and _unparse[x][4] == _unparse[x - 1][4]  # same destPort
    #                     )]
    #         li = [x[9] for x in li]
    #         for i in li:
    #             removed[i] = removed.get(i, 0) + 1
    #         print(removed.keys())
    #
    # else:

    li = [unparse[x] for x in range(1, len(unparse)) if unparse[x][9] != 999 and not (
                unparse[x][0] <= t  # Diff from previous alert is less than x sec
                and unparse[x][1] == unparse[x - 1][1]  # same srcIP
                and unparse[x][3] == unparse[x - 1][3]  # same destIP
                and unparse[x][5] == unparse[x - 1][5]  # same suricata category
                and unparse[x][2] == unparse[x - 1][2]  # same srcPort
                and unparse[x][4] == unparse[x - 1][4]  # same destPort
                )]
    rem = [(unparse[x][9]) for x in range(1, len(unparse)) if
           (unparse[x][0] <= t  # Diff from previous alert is less than x sec
            and unparse[x][1] == unparse[x - 1][1]  # same srcIP
            and unparse[x][3] == unparse[x - 1][3]  # same destIP
            and unparse[x][5] == unparse[x - 1][5]  # same suricata category
            and unparse[x][2] == unparse[x - 1][2]  # same srcPort
            and unparse[x][4] == unparse[x - 1][4]  # same destPort
            )]
    # if plot:
    #     print(orig)
    #     print(removed)
    #     b1 = dict(sorted(orig.items()))
    #     b2 = dict(sorted(removed.items()))
    #     print(b1.keys())
    #     print(b2.keys())
    #     # libraries
    #     import numpy as np
    #     import matplotlib.pyplot as plt
    #     import matplotlib.style
    #     import matplotlib as mpl
    #     mpl.style.use('default')
    #
    #     fig = plt.figure(figsize=(20, 20))
    #
    #     # set width of bar
    #     barWidth = 0.4
    #
    #     # set height of bar
    #     bars1 = [(x) for x in b1.values()]
    #     bars2 = [(x) for x in b2.values()]
    #
    #     # Set position of bar on X axis
    #     r1 = np.arange(len(bars1))
    #     print(r1)
    #     r2 = [x + barWidth for x in r1]
    #     print('--', r2)
    #
    #     # Make the plot
    #     plt.bar(r1, bars1, color='skyblue', width=barWidth, edgecolor='white', label='Raw')
    #     plt.bar(r2, bars2, color='salmon', width=barWidth, edgecolor='white', label='Cleaned')
    #
    #     labs = [micro[x].split('.')[1] for x in b1.keys()]
    #     # print([x for x in b1.keys()])
    #     # print('ticks', [r + barWidth for r in range(len(b1.keys()))])
    #     # Add xticks on the middle of the group bars
    #     plt.ylabel('Frequency', fontweight='bold', fontsize='20')
    #     plt.xlabel('Alert categories', fontweight='bold', fontsize='20')
    #     plt.xticks([x for x in r1], labs, fontsize='20', rotation='vertical')
    #     plt.yticks(fontsize='20')
    #     plt.title('High-frequency Alert Filtering', fontweight='bold', fontsize='20')
    #     # Create legend & Show graphic
    #     plt.legend(prop={'size': 20})
    #     plt.show()

    print('Filtered # alerts (remaining)', len(li))
    return li


def   load_data(path, t, mode=False):
    unparse = []
    team_labels = []
    files = glob.glob(path + "/*.json")
    print('About to read json files...')
    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)
        team_labels.append(name)
        unparse_ = []
        if not mode:
            unparse_ = parse(readfile(f), [], False)
        else:
            # TODO: Check out why reversed was used here
            unparse_ = parse(readfile(f), [], False, mode)
            # unparse_ = parse(reversed(readfile(f)), [], False, mode)
        unparse_ = removeDup(unparse_, t=t)
        unparse.append(unparse_)

    return (unparse, team_labels)
