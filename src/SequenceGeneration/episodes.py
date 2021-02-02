from datetime import datetime
from typing import List, Dict, Tuple

import numpy as np
import matplotlib.pyplot as plt
from math import floor
# Goal: (1) To first form a collective attack profile of a team
# and then (2) TO compare attack profiles of teams
from src.MicroAttackStage import MicroAttackStage
from src.SequenceGeneration.ParsedAlert import ParsedAlert
from src.SequenceGeneration.load import LoadedData
from src.SequenceGeneration.plot import legend_without_duplicate_labels
from src.mappings.mappings import micro, mcols, macro_inv, micro2macro, port_services

from itertools import accumulate


# from src.mappings.IANA_mapping import IANA_mapping
#
#
# class AttackerIDAlert:
#     """
#     Captures an alert from the view of an attacker ID (source IP, dest IP or both)
#     """
#
#     def __init__(self, dest_ip: str, mcat: MicroAttackStage, timestamp: datetime, service: str):
#         self.dest_ip = dest_ip
#         self.mcat = mcat
#         self.timestamp = timestamp
#         self.service = service
#
#
# def _group_by_attacker_victim(data: LoadedData) -> Dict[int, List[(Tuple, AttackerIDAlert)]]:
#     team_data = {}
#     team_alerts = data[0]
#     team_names = data[1]
#     for team_id, alerts in enumerate(team_alerts):
#         host_alerts = {}
#
#         for alert in alerts:
#             dest_port = alert.dest_port or 65000
#             if dest_port not in IANA_mapping:
#                 port_service = "unknown"
#             else:
#                 port_service = IANA_mapping[dest_port].name
#
#             # TODO: allow aggregation by only src or dest
#             alert_id = (alert.src_ip, alert.dest_ip)
#             # Ensure inverse is not already present, if so, put it in the same bin
#             if (alert.dest_ip, alert.src_ip) in host_alerts:
#                 alert_id = (alert.dest_ip, alert.src_ip)
#
#             if alert_id not in host_alerts:
#                 host_alerts[alert_id] = []
#
#             host_alerts[alert_id].append(
#                 AttackerIDAlert(alert_id[1], alert.mcat, alert.timestamp, port_service))
#
#         team_data[team_id] = list(host_alerts.items())
#
#         return team_data
#
#
# def get_attack_episodes(data: LoadedData, step=150):
#     team_data = {}
#     s_t = {}
#
#     team_episodes = []
#     team_data = _group_by_attacker_victim(data)
#
#     # Find start time of each team
#     team_start_times = [alerts[0].timestamp for alerts in data[0]]
#     team_times = []
#
#     mcats = list(micro.keys())
#     mcats_label = [x.split(".")[1] for x in micro.values()]
#
#     for team_id, team_alerts in team_data:
#         print('----------------TEAM ' + str(team_id) + '-------------------------')
#         t_ep = dict()
#
#         # Map attacker ID to (start_time, end_time)
#         _team_times = {}
#         for attacker_id, alerts in team_alerts:
#
#             # Filter out groups of only one alert
#             if len(alerts) <= 1:
#                 continue
#
#             # Normalize start/end time to start at 0
#             first_elapsed_time = round(
#                 (alerts[0].timestamp - team_start_times[team_id]).total_seconds(),
#                 2)
#             last_elapsed_time = round(
#                 (alerts[-1].timestamp - alerts[0].timestamp).total_seconds() + first_elapsed_time,
#                 2)
#
#             _team_times["->".join(attacker_id)] = (first_elapsed_time, last_elapsed_time)
#             timestamps = [alert.timestamp for alert in alerts]
#             rest = alerts
#
#             prev_timestamp = None
#             diff = []
#
#             for timestamp in timestamps:
#                 if prev_timestamp is None:
#                     diff.append(0)
#                 else:
#                     diff.append(round((timestamp - prev_timestamp).total_seconds(), 2))
#
#             assert len(timestamps) == len(diff)
#
#             # List of total time elapsed at the end of each event: [t0, t0+t1, t0+t1+t2]
#             elapsed_time = list(accumulate(diff))
#             relative_elapsed_time = [round(x + first_elapsed_time, 2) for x in elapsed_time]
#
#             assert (len(elapsed_time) == len(diff))
#
#             t_0 = int(first_elapsed_time)  # int(relative_elapsed_time[0])
#             t_n = int(relative_elapsed_time[-1])
#
#             host_episode = []
#             for mcat in mcats:
#                 min_data = []
#
#                 # TODO: optimize
#                 for i in range(t_0, t_n, step):
#                     li = [alert for d, alert in zip(relative_elapsed_time, rest) if
#                           (d >= i and d < (i + step)) and alert.mcat == mcat]
#
#                     min_data.append(li)  # alerts per 'step' seconds
#                 episodes = _get_episodes(min_data, False)
#
#                 if len(episodes) > 0:
#                     pass
#
#
# def _get_episodes(action_sequence: List[List[AttackerIDAlert]], plot: bool) -> List:
#     pass


def getepisodes(action_seq, plot, debug=False):
    dx = 0.1
    # print(h_d_mindata)
    y = [len(x) for x in action_seq]  #
    if not debug:
        # print('-------------- strat')

        if len(y) <= 1:
            # print(sum(y), len(y), 'yo returning')
            return []
            # if (sum(y) > 0):
            ##    print('how long? = ', sum(y))
            #   print(y)
            # fig = plt.figure()
            # plt.plot(y)
            # plt.show()
    # test case 1: normal sequence
    # y = [11, 0, 0, 2, 5, 2, 2, 2, 4, 2, 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 13, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 9, 2]
    # test case 2: start is not detected
    # y = [ 0, 2, 145, 0, 0, 1, 101, 45, 0, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    # test case 2.5: start not detected (unfinfihed)
    # y = [39, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 28, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 1, 1, 2, 1, 2, 2, 1, 1, 1, 2, 0, 1, 2, 0, 2, 1, 1, 1, 2, 1, 1, 0, 1, 1, 1, 1]
    # test case 3: last peak not detected (unfinsihed)
    # y = [36, 0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 17, 0, 0, 0, 0, 0, 0, 33, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 5, 6, 1, 2, 2]
    # test case 4: last peak undetected (finished)
    # y = [1, 0, 0, 1, 3, 0, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 5: end peak is not detected
    # y = [1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 2, 0]
    # test case 6: end peak uncompleted again not detected:
    # y = [8, 4, 0, 0, 0, 4, 0, 0, 5, 0, 0, 1, 10, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2]
    # test case 7: single peak not detected (conjoined)
    # y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 0, 53, 24, 0, 0, 0, 0, 0, 0, 0]
    # test case 8: another single peak not detected
    # y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 9: single peak at the very end
    # y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 294]
    # test acse 10: ramp up at end
    # y = [0, 0, 0, 0, 190, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 271, 272]
    # print(y)
    # y = [1, 0, 64, 2]
    # y = [2, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 0, 2, 3]
    # y = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    cap = max(y) + 1
    dy = np.diff(y) / dx

    dim = len(dy)
    # print(list(zip(y[:dim],dy[:dim])))

    positive = [(0, dy[0])]
    positive.extend([(ind, dy[ind]) for ind in range(1, dim) if
                     (dy[ind - 1] <= 0 and dy[ind] > 0)])  # or ind-1 == 0]
    negative = [(ind + 1, dy[ind + 1]) for ind in range(0, dim - 1) if
                (dy[ind] < 0 and dy[ind + 1] >= 0)]
    if dy[-1] < 0:  # special case for last ramp down thats not fully gone down
        negative.append((len(dy), dy[-1]))
    elif dy[-1] > 0:  # special case for last ramp up without any ramp down
        # print('adding somthing at the end ', (len(dy), dy[-1]))
        negative.append((len(dy), dy[-1]))

    common = list(set(negative).intersection(positive))
    negative = [item for item in negative if item not in common]
    positive = [item for item in positive if item not in common]

    # print('--', [x[0] for x in negative] , len(y))
    negative = [x for x in negative if (y[x[0]] <= 0 or x[0] == len(y) - 1)]
    positive = [x for x in positive if (y[x[0]] <= 0 or x[0] == 0)]

    # print(positive)
    # print(negative)

    if len(negative) < 1 or len(positive) < 1:
        return []

    episodes_ = []  # Tuple (startInd, endInd)
    for i in range(len(positive) - 1):
        ep1 = positive[i][0]
        ep2 = positive[i + 1][0]
        ends = []
        for j in range(len(negative)):

            if negative[j][0] >= ep1 and negative[j][0] < ep2:
                ends.append(negative[j])

        if len(ends) > 0:
            episode = (ep1, max([x[0] for x in ends]))
            episodes_.append(episode)
    if (len(positive) == 1 and len(negative) == 1):
        episode = (positive[0][0], negative[0][0])
        episodes_.append(episode)

    if (len(episodes_) > 0 and negative[-1][0] != episodes_[-1][1]):
        episode = (positive[-1][0], negative[-1][0])
        episodes_.append(episode)

    if (len(episodes_) > 0 and positive[-1][0] != episodes_[-1][
        0]):  # and positive[-1][0] < episodes[-1][1]):
        elim = [x[0] for x in common]
        if len(elim) > 0 and max(elim) > positive[-1][0]:
            episode = (positive[-1][0], max(elim))
            episodes_.append(episode)

    if (len(episodes_) == 0 and len(positive) == 2 and len(negative) == 1):
        episode = (positive[1][0], negative[0][0])
        episodes_.append(episode)

    # if plot:
    #     plt.plot(y, 'gray')
    #     for ep in episodes_:
    #         # print(ep)
    #         xax_start = [ep[0]] * cap
    #         xax_end = [ep[1]] * cap
    #         yax = list(range(cap))
    #
    #         plt.plot(xax_start, yax, 'g', linestyle=(0, (5, 10)))
    #         plt.plot(xax_end, yax, 'r', linestyle=(0, (5, 10)))
    #
    #     plt.show()
    # print('number episodes ', len(episodes_))
    return episodes_


def aggregate_into_episodes(unparse, team_labels, step=150):
    cols = ['b', 'r', 'g', 'c', 'm', 'y', 'k', 'olive', 'lightcoral', 'skyblue', 'mediumpurple',
            'springgreen', 'chocolate', 'cadetblue', 'lavender']

    PRINT = False
    interesting = []
    # Reorganize data for each attacker per team
    team_data = dict()
    s_t = dict()
    for tid, team in enumerate(unparse):
        # attackers = list(set([x[1] for x in team])) # collecting all src ip
        # attackers.extend(list(set([x[3] for x in team]))) # collection all dst ip
        # attackers = [x for x in attackers if x not in hostip.keys()] # filtering only attackers

        host_alerts = dict()

        for ev in team:
            # print(ev[0])
            h = ev[7]
            s = ev[1]
            d = ev[3]
            c = ev[9]
            ts = ev[8]
            sp = ev[2] if ev[2] != None else 65000
            dp = ev[4] if ev[4] != None else 65000
            # Simply respect the source,dst format! (Correction: source is always source and dest alwyas dest!)

            source, dest, port = -1, -1, -1
            # print(s, d, sp, dp)
            # assert sp >= dp

            source = s  # if s not in inv_hostip.keys() else inv_hostip[s]
            dest = d  # if d not in inv_hostip.keys() else inv_hostip[d]
            # explicit name if cant resolve
            # port = str(dp) if (dp not in port_services.keys() or port_services[dp] == 'unknown') else port_services[dp]['name']

            # say unknown if cant resolve it
            port = 'unknown' if (
                    dp not in port_services.keys() or port_services[dp] == 'unknown') else \
                port_services[dp]['name']

            if (source, dest) not in host_alerts.keys() and (
                    dest, source) not in host_alerts.keys():
                host_alerts[(source, dest)] = []
                # print(tid, (source,dest), 'first', ev[8])
                s_t[str(tid) + "|" + str(source) + "->" + str(dest)] = ev[8]

            if ((source, dest) in host_alerts.keys()):
                host_alerts[(source, dest)].append(
                    (dest, c, ts, port))  # TODO: remove the redundant host names
                # print(source, dest, (micro[c].split('.'))[-1], port)
            else:
                host_alerts[(dest, source)].append((source, c, ts, port))
                # print(dest,source, (micro[c].split('.'))[-1], port)

        team_data[tid] = host_alerts.items()

    # Note: Calculate number of alerts over time for each attacker
    # print(len(s_t))
    team_episodes = []

    startTimes = [x[0][8] for x in unparse]
    team_times = []

    mcats = list(micro.keys())
    mcats_lab = [x.split('.')[1] for x in micro.values()]
    for tid, team in team_data.items():
        print('----------------TEAM ' + str(tid) + '-------------------------')
        t_ep = dict()
        _team_times = dict()
        for attacker, alerts in team:
            # Note: Alert is tuple (dest_ip, mcat, ts, port_service)
            # if re.search('[a-z]', attacker):
            #    continue
            # if attacker != ('corp-mail-00', 'corp-onramp-00'):
            #    continue

            if len(alerts) <= 1:
                # print('kill ', attacker)
                continue

            # print(attacker, len([(x[1]) for x in alerts])) # TODO: what about IPs that are not attacker related?
            first_elapsed_time = round((alerts[0][2] - startTimes[tid]).total_seconds(), 2)

            # debugging if start times of each connection are correct.
            # print(first_elapsed_time, round( (s_t[str(tid)+"|"+str(attacker[0])+"->"+str(attacker[1])] - startTimes[tid]).total_seconds(),2))
            last_elapsed_time = round(
                (alerts[-1][2] - alerts[0][2]).total_seconds() + first_elapsed_time, 2)
            # print(first_elapsed_time, last_elapsed_time)

            # Note: Maps attacker id to (start_time, end_time) tuples, normalized over start time of the team
            _team_times['->'.join(attacker)] = (first_elapsed_time, last_elapsed_time)
            ts = [x[2] for x in alerts]
            rest = [(x[0], x[1], x[2], x[3]) for x in alerts]

            prev = -1
            # Note: Time difference to previous alert within this set
            DIFF = []
            relative_elapsed_time = []
            for timeid, dt in enumerate(ts):
                if timeid == 0:
                    DIFF.append(0.0)  # round((dt - startTimes[tid]).total_seconds(),2) )
                else:
                    DIFF.append(round((dt - prev).total_seconds(), 2))
                prev = dt
            # print(DIFF[:5])
            assert (len(ts) == len(DIFF))
            elapsed_time = list(accumulate(DIFF))
            relative_elapsed_time = [round(x + first_elapsed_time, 2) for x in elapsed_time]
            # Note: relative_elapsed_time are the relative times of this alert list, with t=0 being the team start time
            assert (len(elapsed_time) == len(DIFF))

            t0 = int(first_elapsed_time)  # int(relative_elapsed_time[0])
            tn = int(relative_elapsed_time[-1])

            # step = 150 # 2.5 minute fixed step. Can be reduced or increased depending on required granularity

            h_ep = []
            # mindatas = []
            for mcat in mcats:
                # Note: construct a list of windows over (t0, tn, step)
                mindata = []
                for i in range(t0, tn, step):
                    li = [a for d, a in zip(relative_elapsed_time, rest) if
                          (d >= i and d < (i + step)) and a[1] == mcat]
                    mindata.append(li)  # alerts per 'step' seconds

                # print([len(x) for x in mindata])
                episodes = []

                # Note: each episode is a tuple of index (based on mindata) before and after the ep
                episodes = getepisodes(mindata, False)

                if len(episodes) > 0:

                    events = [len(x) for x in mindata]
                    # Note: Construct time window as tuple (start,end) for all non-empty windows
                    minute_info = [(x[0] * step + t0, x[1] * step + t0) for x in episodes]

                    # Note: Get all ports in each window
                    raw_ports = []
                    for e in mindata:
                        if len(e) > 0:
                            raw_ports.append([(x[3]) for x in e])
                        else:
                            raw_ports.append([])
                    # Note: Converts raw_ports to one big list, (flatten nested list)
                    _flat_ports = [item for sublist in raw_ports for item in sublist]
                    # Note: each episode is (start_time, end_time, mcat, ...,
                    episode = [(mi[0], mi[1], mcat, events[x[0]:x[1] + 1],
                                raw_ports[x[0]:x[1] + 1])
                               for x, mi in zip(episodes,
                                                minute_info)]  # now the start and end are actual elapsed times
                    # Note: Flattens the raw_ports nested list
                    # EPISODE DEF: (startTime, endTime, mcat, rawevents, epiVolume, epiPeriod, epiServices)
                    episode = [(x[0], x[1], x[2], x[3], round(sum(x[3]) / float(len(x[3])), 1),
                                (x[1] - x[0]),
                                [item for sublist in x[4] for item in sublist]) for x in episode]

                    h_ep.extend(episode)

            if len(h_ep) == 0:
                continue
            # Note: artificially adding tiny delay for events that are exactly at the same time
            h_ep.sort(key=lambda tup: tup[0])
            minute_info = [x[0] for x in h_ep]
            minute_info2 = [minute_info[0]]
            tiny_delay = 1
            for i in range(1, len(minute_info)):
                if i == 0:
                    pass
                else:
                    if (minute_info[i] == (minute_info[i - 1])):
                        minute_info2.append(minute_info2[-1] + tiny_delay)
                    else:
                        minute_info2.append(minute_info[i])
            h_ep = [(minute_info2[i], x[1], x[2], x[3], x[4], x[5], x[6]) for i, x in
                    enumerate(h_ep)]
            t_ep[attacker] = h_ep
            if PRINT:
                fig = plt.figure(figsize=(10, 10))
                ax = plt.gca()
                plt.title('Micro attack episodes | Team: ' + str(tid) + ' | Host: ' + '->'.join(
                    [x for x in attacker]))
                plt.xlabel('Time Window (sec)')
                plt.ylabel('Micro attack stages')
                # NOTE: Line thicknesses are on per host basis
                tmax = max([x[4] for x in h_ep])
                tmin = min([x[4] for x in h_ep])
                for idx, ep in enumerate(h_ep):
                    # print(idx, (ep[0], ep[1]), ep[2], ep[3][ep[0]:ep[1]+1])
                    xax = list(range(ep[0], ep[1] + 1))
                    yax = [mcats.index(ep[2])] * len(xax)
                    thickness = ep[4]
                    lsize = ((thickness - tmin) / (tmax - tmin)) * (5 - 0.5) + 0.5 if (
                                                                                              tmax - tmin) != 0.0 else 0.5
                    # lsize = np.log(thickness) + 1 TODO: Either take log or normalize between [0.5 5]
                    msize = (lsize * 2) + 1
                    ax.plot(xax, yax, color=mcols[macro_inv[micro2macro[micro[ep[2]]]]],
                            linewidth=lsize)
                    ax.plot(ep[0], mcats.index(ep[2]),
                            color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.',
                            linewidth=0, markersize=msize, label=micro2macro[micro[ep[2]]])
                    ax.plot(ep[1], mcats.index(ep[2]),
                            color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.',
                            linewidth=0, markersize=msize)
                    plt.yticks(range(len(mcats)), mcats_lab, rotation='0')
                legend_without_duplicate_labels(ax)
                plt.grid(True, alpha=0.4)

                # plt.tight_layout()
                # plt.savefig('Pres-Micro-attack-episodes-Team'+str(tid) +'-Connection'+ attacker[0]+'--'+attacker[1]+'.png')
                plt.show()
        # Note: t_ep is a dict of (attacker_id -> episode sequence)
        #       team_times is a dict of (attacker_id -> (start_time, end_time)
        team_episodes.append(t_ep)
        team_times.append(_team_times)
    return (team_episodes, team_times)


## 17

#### Host = [connections] instead of team level representation
def host_episode_sequences(team_episodes):
    host_data = {}
    # team_host_data= []
    print(len(team_episodes))

    for tid, team in enumerate(team_episodes):
        print('----- TEAM ', tid, ' -----')
        print(len(set([x[0] for x in team.keys()])))
        for attacker, episodes in team.items():
            # print(attacker)
            if len(episodes) < 2:
                continue
            perp = attacker[0]
            vic = attacker[1]
            # print(perp)
            # if ('10.0.0' in perp or '10.0.1' in perp):
            #        continue

            att = 't' + str(tid) + '-' + perp
            # print(att)
            if att not in host_data.keys():
                host_data[att] = []
            ext = [(x[0], x[1], x[2], x[3], x[4], x[5], x[6], vic) for x in episodes]

            host_data[att].append(ext)
            host_data[att].sort(key=lambda tup: tup[0][0])

    print(len(host_data))

    team_strat = list(host_data.values())
    # print(len(team_strat[0]), [(len(x)) for x in team_strat[0]])
    # print([[a[2] for a in x] for x in team_strat[0]])
    return (host_data)


def break_into_subbehaviors(host_data):
    attackers = []
    keys = []
    alerts = []
    cutlen = 4
    FULL_SEQ = False

    # print(len(team))
    for tid, (atta, victims) in enumerate(host_data.items()):
        print('----- Sequence # ', tid, ' -----')
        # print(atta)
        # print(len(victims))
        for episodes in victims:
            if len(episodes) < 2:
                continue
            victim = episodes[0][7]
            pieces = floor(len(episodes) / cutlen)
            _episodes = []
            if FULL_SEQ:
                att = atta + '->' + victim
                # print(att, [x[2] for x in episodes])
                keys.append(att)
                alerts.append(episodes)

            else:
                if pieces < 1:
                    att = atta + '->' + victim + '-0'
                    # print('---', att, [x[2] for x in episodes])
                    keys.append(att)
                    alerts.append(episodes)
                else:
                    c = 0
                    ep = [x[2] for x in episodes]
                    # print(ep)
                    cuts = [i for i in range(len(episodes) - 1) if (len(str(ep[i])) > len(
                        str(ep[i + 1])))]  # (ep[i] > 100 and ep[i+1] < 10)]
                    # print(cuts)
                    if len(cuts) == 0:
                        att = atta + '->' + victim + '-0'
                        # print('---', att, [x[2] for x in episodes])
                        keys.append(att)
                        alerts.append(episodes)
                        # pass
                    else:
                        rest = (-1, -1)

                        for i in range(len(cuts)):
                            start, end = 0, 0
                            if i == 0:
                                start = 0
                                end = cuts[i]
                            else:
                                start = cuts[i - 1] + 1
                                end = cuts[i]
                            rest = (end + 1, len(ep) - 1)
                            al = episodes[start:end + 1]
                            if len(al) < 2:
                                print('discrding-1', [x[2] for x in al], start, end, len(episodes))
                                continue
                            att = atta + '->' + victim + '-' + str(c)
                            # print('---', att, [x[2] for x in al])
                            keys.append(att)
                            alerts.append(al)
                            c += 1
                        # print('--', ep[rest[0]: rest[1]+1])
                        al = episodes[rest[0]: rest[1] + 1]
                        if len(al) < 2:
                            print('discrding-2', [x[2] for x in al])  # TODO This one is not cool1
                            continue
                        att = atta + '->' + victim + '-' + str(c)
                        # print('---', att, [x[2] for x in al])
                        keys.append(att)
                        alerts.append(al)
    print('# sub-sequences', len(keys))
    return (alerts, keys)
