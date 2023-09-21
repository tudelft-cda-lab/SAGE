import math
from itertools import accumulate

import numpy as np

from plotting import plot_episodes, plot_alert_volume_per_episode
from signatures.mappings import micro


def _get_ups_and_downs(frequencies, slopes):
    positive = [(0, slopes[0])]  # (index, slope)
    positive.extend([(i, slopes[i]) for i in range(1, len(slopes)) if (slopes[i - 1] <= 0 and slopes[i] > 0)])
    negative = [(i + 1, slopes[i + 1]) for i in range(0, len(slopes) - 1) if (slopes[i] < 0 and slopes[i + 1] >= 0)]
    if slopes[-1] < 0:  # Special case for last ramp down that's not fully gone down
        negative.append((len(slopes), slopes[-1]))
    elif slopes[-1] > 0:  # Special case for last ramp up without any ramp down
        negative.append((len(slopes), slopes[-1]))
    elif slopes[-1] == 0 and frequencies[-1] != 0:  # Special case where last slope is 0, but it is not the global min
        negative.append((len(slopes), slopes[-1]))

    common = set(negative).intersection(positive)
    negative = [item for item in negative if item not in common]
    positive = [item for item in positive if item not in common]

    negative = [x for x in negative if (frequencies[x[0]] == 0 or x[0] == len(frequencies) - 1)]
    positive = [x for x in positive if (frequencies[x[0]] == 0 or x[0] == 0)]
    return positive, negative, common


# Goal: (1) To first form a collective attack profile of a team
# and then (2) To compare attack profiles of teams
def _get_episodes(alert_seq, mcat, plot=False):
    # x-axis represents the time, y-axis represents the frequencies of alerts within a window
    dx = 0.1
    frequencies = [len(x) for x in alert_seq]

    # TODO: move these test cases into a separate test file
    # test case 1: normal sequence
    #y = [11, 0, 0, 2, 5, 2, 2, 2, 4, 2, 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 13, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 9, 2]
    # test case 2: start is not detected
    #y = [ 0, 2, 145, 0, 0, 1, 101, 45, 0, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    # test case 2.5: start not detected (unfinished)
    #y = [39, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 28, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 1, 1, 2, 1, 2, 2, 1, 1, 1, 2, 0, 1, 2, 0, 2, 1, 1, 1, 2, 1, 1, 0, 1, 1, 1, 1]
    # test case 3: last peak not detected (unfinished)
    #y = [36, 0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 17, 0, 0, 0, 0, 0, 0, 33, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 5, 6, 1, 2, 2]
    # test case 4: last peak undetected (finished)
    #y = [1, 0, 0, 1, 3, 0, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 5: end peak is not detected
    #y = [1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 2, 0]
    # test case 6: end peak uncompleted again not detected:
    #y = [8, 4, 0, 0, 0, 4, 0, 0, 5, 0, 0, 1, 10, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2]
    # test case 7: single peak not detected (conjoined)
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 0, 53, 24, 0, 0, 0, 0, 0, 0, 0]
    # test case 8: another single peak not detected
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 9: single peak at the very end
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 294]
    # test case 10: ramp up at end
    #y = [0, 0, 0, 0, 190, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 271, 272]
    #print(y)
    #y = [1, 0, 64, 2]
    #y = [2, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 0, 2, 3]
    #y = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    if sum(frequencies) == 0:
        return []
    if len(frequencies) == 1:  # Artificially augmenting list for a single action to be picked up
        frequencies = [frequencies[0], 0]

    slopes = np.diff(frequencies) / dx  # Taking derivative of frequencies
    positive, negative, common = _get_ups_and_downs(frequencies, slopes)

    if len(negative) < 1 or len(positive) < 1:
        return []

    # Get episodes (down between ups)
    episodes = []  # Tuple (start_index, end_index)
    for i in range(len(positive) - 1):
        ep1 = positive[i][0]
        ep2 = positive[i + 1][0]
        ends = []
        for j in range(len(negative)):
            if ep1 <= negative[j][0] < ep2:
                ends.append(negative[j])

        if len(ends) > 0:
            episode = (ep1, max([x[0] for x in ends]))
            episodes.append(episode)

    # Handle edge cases
    if len(positive) == 1 and len(negative) == 1:
        episode = (positive[0][0], negative[0][0])
        episodes.append(episode)

    if len(episodes) > 0 and negative[-1][0] != episodes[-1][1]:
        episode = (positive[-1][0], negative[-1][0])
        episodes.append(episode)

    if len(episodes) > 0 and positive[-1][0] != episodes[-1][0]:
        elim = [x[0] for x in common]
        if len(elim) > 0 and max(elim) > positive[-1][0]:
            episode = (positive[-1][0], max(elim))
            episodes.append(episode)

    if len(episodes) == 0 and len(positive) == 2 and len(negative) == 1:
        episode = (positive[1][0], negative[0][0])
        episodes.append(episode)

    if plot:
        plot_episodes(frequencies, episodes, mcat)

    return episodes


def _create_episode(hyperalert_seq_epi, mcat, team_start_time):
    # Flatten relevant data from the windows of the corresponding alert sequence
    services = [alert[3] for window in hyperalert_seq_epi for alert in window]
    unique_signatures = list(set([alert[4] for window in hyperalert_seq_epi for alert in window]))
    events = [len(window) for window in hyperalert_seq_epi]
    alert_volume = round(sum(events) / float(len(events)), 1)

    # Make exact start/end times based on alert timestamps
    timestamps = [alert[2] for window in hyperalert_seq_epi for alert in window]
    first_ts, last_ts = min(timestamps), max(timestamps)

    # Make the start/end times the actual elapsed times
    start_time = (first_ts - team_start_time).total_seconds()
    end_time = (last_ts - team_start_time).total_seconds()
    period = end_time - start_time

    # EPISODE DEF: (startTime, endTime, mcat, raw_events, volume(alerts), epiPeriod, epiServices, list of unique signatures, (1st timestamp, last timestamp)
    episode = (start_time, end_time, mcat, events, alert_volume, period, services, unique_signatures, (first_ts, last_ts))
    return episode


# Step 2: Create alert sequence and get episodes
def aggregate_into_episodes(team_data, start_times, step=150, plot=False, plot_alert_volumes=False):
    team_episodes = []
    team_times = []

    print('---------------- TEAMS -------------------------')

    mcats = list(micro.keys())
    for tid, team in team_data.items():
        print(tid, sep=' ', end=' ', flush=True)
        team_host_episodes = dict()
        _team_times = dict()
        for attacker_victim, alerts in team:
            if len(alerts) <= 1:
                continue

            # Alert format: (dst_ip, mcat, ts, dst_port, signature)
            # print(attacker_victim, len([(x[1]) for x in alerts])) # TODO: what about IPs not related to attacker?
            first_elapsed_time = round((alerts[0][2] - start_times[tid]).total_seconds(), 2)

            _team_times['->'.join(attacker_victim)] = first_elapsed_time

            ts = [x[2] for x in alerts]
            diff_ts = [0.0]
            for i in range(1, len(ts)):
                diff_ts.append(round((ts[i] - ts[i - 1]).total_seconds(), 2))
            elapsed_time = list(accumulate(diff_ts))
            relative_elapsed_time = [round(x + first_elapsed_time, 2) for x in elapsed_time]

            host_episodes = []
            for mcat in mcats:
                # 2.5-minute (150s) fixed step (window). Can be reduced or increased depending on required granularity
                hyperalert_seq = []
                for i in range(int(first_elapsed_time), int(relative_elapsed_time[-1]), step):
                    window = [a for dt, a in zip(relative_elapsed_time, alerts) if (i <= dt < (i + step)) and a[1] == mcat]
                    hyperalert_seq.append(window)  # Alerts per 'step' seconds (window)

                raw_episodes = _get_episodes(hyperalert_seq, micro[mcat], plot=plot)
                if len(raw_episodes) > 0:
                    for epi in raw_episodes:
                        hyperalert_seq_epi = hyperalert_seq[epi[0]:epi[1]+1]
                        episode = _create_episode(hyperalert_seq_epi, mcat, start_times[tid])
                        host_episodes.append(episode)

            if len(host_episodes) == 0:
                continue

            host_episodes.sort(key=lambda tup: tup[0])
            team_host_episodes[attacker_victim] = host_episodes

            if plot_alert_volumes:
                plot_alert_volume_per_episode(tid, attacker_victim, host_episodes, mcats)

        team_episodes.append(team_host_episodes)
        team_times.append(_team_times)
    return team_episodes, team_times


# Step 3: Create episode sequences
# Host = [connections] instead of team level representation
def host_episode_sequences(team_episodes):
    host_data = {}
    print('# teams:', len(team_episodes))
    print('----- TEAMS -----')
    for tid, team in enumerate(team_episodes):
        print(tid, sep=' ', end=' ', flush=True)
        for (attacker, victim), episodes in team.items():
            # if ('10.0.0' in attacker or '10.0.1' in attacker):
            #        continue

            att = 't' + str(tid) + '-' + attacker
            if att not in host_data.keys():
                host_data[att] = []

            extended_episode = [epi + (victim,) for epi in episodes]

            host_data[att].append(extended_episode)
            host_data[att].sort(key=lambda tup: tup[0][0])

    print('\n# episode sequences:', len(host_data))
    return host_data


# Step 4.1: Split episode sequences for an attacker-victim pair into episode subsequences.
# Each episode subsequence represents an attack attempt.
def break_into_subbehaviors(host_data, full_seq=False):
    subsequences = dict()

    print('----- Sub-sequences -----')
    for i, (attacker, victim_episodes) in enumerate(host_data.items()):
        print((i + 1), sep=' ', end=' ', flush=True)
        for episodes in victim_episodes:
            if len(episodes) < 2:
                continue

            victim = episodes[0][-1]
            attacker_victim = attacker + '->' + victim
            if full_seq:
                subsequences[attacker_victim] = episodes
                continue
            if len(episodes) == 1:
                subsequences[attacker_victim + '-0'] = episodes
                continue

            # This part of the code only needs to cut the sequences at appropriate places -- no discarding is needed.
            # The discarding already happens later in make_attack_graphs.
            # So here, the viable cuts are: [med, low], [high, low], and [high, med].
            # For the latter two cases, we will see the first subsequence in the AGs related to the objective = high.
            # For the first case, unless AGs are also made for medium severity objectives,
            #   they will not be appearing anywhere (and we call them partial paths).
            count = 0
            mcats = [epi[2] for epi in episodes]
            cuts = [i for i in range(len(episodes) - 1) if (len(str(mcats[i])) > len(str(mcats[i + 1])))]

            rest = (0, len(episodes) - 1)
            for j in range(len(cuts)):
                start = 0 if j == 0 else cuts[j - 1] + 1
                end = cuts[j]
                rest = (end + 1, len(episodes) - 1)
                subsequence = episodes[start:end+1]
                subsequences[attacker_victim + '-' + str(count)] = subsequence
                count += 1
            subsequence = episodes[rest[0]:rest[1]+1]
            subsequences[attacker_victim + '-' + str(count)] = subsequence

    print('\n# sub-sequences:', len(subsequences))
    return subsequences
