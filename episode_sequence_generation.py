from itertools import accumulate

import numpy as np

from plotting import plot_episodes, plot_alert_volume_per_episode
from signatures.mappings import micro


def _get_ups_and_downs(frequencies, slopes):
    """
    Gets the positive and negative slopes as part of the episode generation, as defined in the paper, i.e.:
    - when the frequency starts to increase (an up), we consider it the start of an episode
    - when the frequency is continuously decreasing reaching a global minimum (a down),
        we consider it the end of that episode

    @param frequencies: the frequencies of the alerts in the corresponding alert windows
    @param slopes: the slopes of the alerts in the corresponding alert windows
    @return: positive and negative slopes (lists of (index, slope)) and their intersection
    """
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


def _get_episodes(alert_seq, mcat, plot=False):
    """
    Gets the episodes from the given (hyper)alert sequence. An episode in this function is (start_index, end_index).
    The goal is to: (1) first form a collective attack profile of a team, and then
                    (2) compare attack profiles of teams

    @param alert_seq: the (hyper)alert sequence for the current attacker-victim pair and mcat
    @param mcat: the attack stage for the episodes
    @param plot: whether to plot the episode slopes for the given (hyper)alert sequence
    @return: the episodes for the given (hyper)alert sequence
    """
    # x-axis represents the time, y-axis represents the frequencies of alerts within a window
    dx = 0.1
    frequencies = [len(x) for x in alert_seq]

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
    """
    Creates an episode with all the required information based on the corresponding fragment of the alert sequence.
    The format of an episode: (startTime, endTime, mcat, raw_events, volume(alerts), epiPeriod,
                                epiServices, list of unique signatures, (1st timestamp, last timestamp).

    @param hyperalert_seq_epi: the fragment of the (hyper)alert sequence for the given attacker-victim pair and mcat
    @param mcat: the attack stage of the episodes
    @param team_start_time: the first timestamp of the given team
    @return: the created episode with all the required information
    """
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
    """
    Converts the alerts (grouped per team and attacker-victim pair) into episodes.
    Each episode is likely to correspond to a single attacker action.

    @param team_data: the alerts grouped by team and attacker-victim pair
    @param start_times: the first timestamp for each team
    @param step: the alert aggregation window (aka w, default: 150 sec)
    @param plot: whether to plot the episode slopes for the given (hyper)alert sequence
    @param plot_alert_volumes: whether to plot the alert volume per episode for each attacker-victim pair and mcat
    @return: episodes and the first elapsed time for each attacker-victim pair and mcat, both grouped by team
    """
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
                        hyperalert_seq_epi = hyperalert_seq[epi[0]:epi[1] + 1]
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
def host_episode_sequences(team_episodes):
    """
    Convert the created episodes into episode sequences grouped per attacker host (e.g. 't0-10.0.254.30': <episodes>).
    Host = [connections] instead of team level representation.

    @param team_episodes: episodes for each attacker-victim pair and mcat, grouped by team
    @return: episode sequences grouped by attacker host (victim is appended to the episode data)
    """
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
def break_into_subbehaviors(host_data, full_seq=False):
    """
    Cuts the episode sequences into episode subsequences. Each episode subsequence represents an attack attempt.

    @param host_data: episode sequences per attacker host
    @param full_seq: whether to use full episode sequences (i.e. do not cut into episode subsequences)
    @return: episode subsequences per attacker-victim pair
    """
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
                subsequence = episodes[start:end + 1]
                subsequences[attacker_victim + '-' + str(count)] = subsequence
                count += 1
            subsequence = episodes[rest[0]:rest[1] + 1]
            subsequences[attacker_victim + '-' + str(count)] = subsequence

    print('\n# sub-sequences:', len(subsequences))
    return subsequences
