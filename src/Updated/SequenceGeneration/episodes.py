from datetime import datetime
from typing import List, Dict, Tuple, Optional

from src.Updated.MicroAttackStage import MicroAttackStage
from src.Updated.SequenceGeneration.ParsedAlert import ParsedAlert
from src.Updated.SequenceGeneration.load import LoadedData
from src.Updated.mappings.IANA_mapping import IANA_mapping


class GroupedAlert:
    def __init__(self, src_ip: str, dest_ip: str, mcat: MicroAttackStage, timestamp: datetime,
                 service: str):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.mcat = mcat
        self.timestamp = timestamp
        self.service = service

    def __str__(self) -> str:
        return f"{self.src_ip}->{self.dest_ip}; {self.mcat.name}|{self.service} {self.timestamp}"


class AttackEpisode:
    def __init__(self, start_time: int, end_time: int, mcat: MicroAttackStage,
                 services: List[str], alerts: List[GroupedAlert]):
        """
        Represents one attack episode.

        :param start_time: relative start time of first window in the episode
        :param end_time: relative end time of the last window in the episode
        :param mcat: attack stage of all attacks
        :param services: services related to the alerts in this episode
        :param alerts: the GroupedAlert objects contained in this window
        """
        self.start_time = start_time
        self.end_time = end_time
        self.mcat = mcat
        self.services = services
        self.alerts = alerts

    def __str__(self):
        return f"{self.start_time}--{self.end_time}; {len(self.alerts)} alerts; {self.mcat}; {self.services}"

    def first_alert_time(self, start_time: Optional[datetime] = None):
        """
        Gets the time of the first alert in the window.

        If start_time is defined, the returned value is the number of seconds after start_time
        """
        if start_time is None:
            return self.alerts[0].timestamp
        else:
            return round((self.alerts[0].timestamp - start_time).total_seconds(), 2)

    def last_alert_time(self, start_time: Optional[datetime] = None):
        """
        Gets the time of the last alert in the window.

        If start_time is defined, the returned value is the number of seconds after start_time
        """
        if start_time is None:
            return self.alerts[-1].timestamp
        else:
            return round((self.alerts[-1].timestamp - start_time).total_seconds(), 2)


TeamAttackEpisodes = Dict[int, Dict[Tuple, List[AttackEpisode]]]


def get_attack_episodes(parsed_data: LoadedData, time_step=150) -> TeamAttackEpisodes:
    res = {}

    for idx in range(len(parsed_data[0])):
        team_alerts = parsed_data[0][idx]
        team_name = parsed_data[1][idx]
        res[idx] = {}

        print(f"Evaluating {idx}: team {team_name}")

        team_start = team_alerts[0].timestamp
        grouped_alerts = _group_by_attacker_victim(team_alerts)

        for attacker_id, alerts in grouped_alerts.items():
            attack_sequences = _to_attack_episodes(alerts, team_start, time_step=time_step)
            if len(attack_sequences) > 0:
                res[idx][attacker_id] = attack_sequences
    return res


GroupedAlerts = Dict[Tuple, List[GroupedAlert]]


def _group_by_attacker_victim(alerts: List[ParsedAlert]) -> GroupedAlerts:
    """
    Processes a list of alerts by aggregating them based on attacker,victim combination.
    Dealing with different teams must be done outside this function.

    See slide 7 from the presentation

    :param alerts: Input list of alerts from one team
    """

    grouped_alerts = {}

    for alert in alerts:
        dest_port = alert.dest_port or 65000
        if dest_port not in IANA_mapping:
            port_service = "unknown"
        else:
            port_service = IANA_mapping[dest_port].name

        # TODO: allow aggregation by only src or dest
        alert_id = (alert.src_ip, alert.dest_ip)
        # Ensure inverse is not already present, if so, put it in the same bin
        if (alert.dest_ip, alert.src_ip) in grouped_alerts:
            alert_id = (alert.dest_ip, alert.src_ip)

        if alert_id not in grouped_alerts:
            grouped_alerts[alert_id] = []

        grouped_alerts[alert_id].append(
            GroupedAlert(alert_id[0], alert_id[1], alert.mcat, alert.timestamp, port_service))

    # Remove all combos with a lack of alerts
    return {attacker: attacker_alerts for attacker, attacker_alerts in grouped_alerts.items() if
            len(attacker_alerts) > 1}
    #
    # return grouped_alerts


def _to_attack_episodes(alerts: List[GroupedAlert], team_start: datetime, time_step: int) -> \
        List[AttackEpisode]:
    """
    Splits the list of alerts based on Micro attack stage (mcat)

    See slide 8 from the presentation, top two figures

    :param alerts: List of alerts for which the grouping (src_ip, dest_ip or both) is equal
    :returns: List
    """
    # Sanity check: verify the data is consistent
    for i in range(1, len(alerts)):
        assert alerts[i].src_ip == alerts[i - 1].src_ip
        assert alerts[i].dest_ip == alerts[i - 1].dest_ip

    # Verify all alerts are spread out enough -> not all fit in only one window
    #  Base.episodes.py: line 18
    if (alerts[-1].timestamp - alerts[0].timestamp).total_seconds() < time_step:
        return []

    # Step 1: split on mcat
    # Split the list of alerts based on micro attack stage
    mcat_to_alerts = {}
    for alert in alerts:
        if alert.mcat not in mcat_to_alerts:
            mcat_to_alerts[alert.mcat] = []
        mcat_to_alerts[alert.mcat].append(alert)

    # Step 2: assign to windows and split based on density
    all_episodes = []
    for mcat, mcat_alerts in mcat_to_alerts.items():
        all_episodes += _split_to_episodes(mcat_alerts, team_start, alerts[0].timestamp, time_step)

    # Step 3: sort on episode start time
    # Sort the episodes on start time, and use mcat severity as a tie breaker
    def _episode_sorting_key(episode: AttackEpisode) -> Tuple[int, MicroAttackStage]:
        return episode.start_time, episode.mcat

    all_episodes = sorted(all_episodes, key=_episode_sorting_key)
    if len(all_episodes) == 0:
        return []

    # TODO: See why this is needed
    #  -> This ensures the start time for a window is moved up to 0 (case [1, 0] over [0, 1, 0])
    #  or the end time is within limits (case [0, 1] vs [0, 1, 0]) -> should not be necessary
    min_ts = all_episodes[0].start_time
    max_ts = all_episodes[0].end_time
    for ep in all_episodes:
        min_ts = min(min_ts, ep.start_time)
        max_ts = max(max_ts, ep.end_time)
    for ep in all_episodes:
        if ep.start_time == min_ts:
            ep.start_time += time_step
        if ep.end_time == max_ts:
            ep.end_time -= time_step

    def _episode_sorting_key(episode: AttackEpisode) -> Tuple[int, MicroAttackStage]:
        return episode.start_time, episode.mcat

    all_episodes = sorted(all_episodes, key=_episode_sorting_key)

    # Artificially delay windows starting at the same time
    start_times = set()
    max_start_time = -1
    for ep in all_episodes:

        if ep.start_time in start_times:
            ep.start_time = max_start_time + 1
            max_start_time += 1
        else:
            start_times.add(ep.start_time)
            max_start_time = ep.start_time

    return all_episodes


class _AlertWindow:
    """
    Type helper to represent a window in the generation of attack episodes.
    """

    def __init__(self, start_time: int, alerts: List[GroupedAlert]):
        """
        :param start_time: Relative start time of the window
        :param alerts: List of all alerts in the window
        """
        self.start_time = start_time
        self.size = len(alerts)
        self.alerts = alerts

    def __str__(self):
        return f"AlertWindow {self.start_time}, {self.size} alerts"


def _split_to_episodes(alerts: List[GroupedAlert], team_start: datetime,
                       attacker_id_start: datetime, time_step: int) -> List[AttackEpisode]:
    """
    Converts a list of alerts all with the same attacker id and mcat to a list of attack episodes.
    First, the alerts are assigned to windows, which are then split based on temporal density
    to form the different attack episodes.

    All input alerts should have the same attacker id and same mcat, and must be sorted on timestamp
    :param alerts List of alerts SORTED ON TIMESTAMP
    :param team_start: Timestamp of the first alert of this team, used for aligning the windows
    :param attacker_id_start: Timestamp of the first alert for this attacker id
    :param time_step Size of the window to use
    """
    # Used for sanity check: all alerts have the same mcat and are in increasing order
    mcat = alerts[0].mcat
    previous_ts = alerts[0].timestamp

    # Check when this alert sequence (which is for one (src_ip, dest_ip) combination) starts
    #  -> used to align the window
    attacker_id_offset = int((attacker_id_start - team_start).total_seconds())

    current_window_start = 0
    window_alerts: List[GroupedAlert] = []
    # List of tuples (start_time, window_size, [alerts]) for each non-empty window
    windows: List[_AlertWindow] = []
    for alert in alerts:
        # Sanity check
        assert alert.mcat == mcat
        assert alert.timestamp >= previous_ts
        previous_ts = alert.timestamp

        # Compute start time relative to the beginning of this set of alerts
        relative_start = int((alert.timestamp - attacker_id_start).total_seconds())
        window_start = attacker_id_offset + relative_start - (relative_start % time_step)
        if window_start == current_window_start:
            # Alert falls in the same window as the previous alert, so add it to the window
            window_alerts.append(alert)
        else:
            # Alert is part of the next window
            if len(window_alerts) > 0:
                # Add the previous window to the list of windows
                windows.append(_AlertWindow(current_window_start, window_alerts))
            # Reset to start constructing the new window
            current_window_start = window_start
            window_alerts = [alert]

    # Also add the final window to the list
    if len(window_alerts) > 0:
        windows.append(_AlertWindow(current_window_start, window_alerts))

    return _windows_to_episodes(windows, time_step)


def _windows_to_episodes(windows: List[_AlertWindow], time_step: int) -> List[AttackEpisode]:
    """
    Converts a list of windowed alerts to a set of episodes.

    For splitting, a naive approach is used. Under the assumption that the global minimum window
    size is 0 (there is some interval with no alerts), windows can be split based on gaps of two
    in the window sequence.

    :param windows: List of windowed alerts
    :param time_step: Length of each window
    """
    # Sanity check: all windows are non-empty
    for window in windows:
        assert window.size > 0
        assert window.size == len(window.alerts)

    # Check: see if the window sequence has gaps. If so, the global minimum window size is 0, and we
    #  don't have to bother with the derivative, but instead can split based on gaps.
    # Alternative: if there is only one window, there is no problem
    # TODO: Check -> seems to be removed
    has_gap = len(windows) == 1
    for i in range(1, len(windows)):
        # Check if the previous window started more than one time step away.
        if windows[i - 1].start_time + 2 * time_step != windows[i].start_time:
            has_gap = True
            break
    # List is one long episode -> return nothing (Base.episodes.py, line 82)
    # if not has_gap:
    #     return []

    res: List[AttackEpisode] = []
    current_episode_windows = [windows[0]]  # Add first window to the first episode
    for window in windows[1:]:
        if current_episode_windows[-1].start_time + 2 * time_step >= window.start_time:
            # This window directly follows the previous window -> they belong to the same episode
            current_episode_windows.append(window)
        else:
            res.append(_to_episode(current_episode_windows, time_step))
            current_episode_windows = [window]
    # Add last window to episodes
    res.append(_to_episode(current_episode_windows, time_step))

    return res


def _to_episode(windows: List[_AlertWindow], time_step: int) -> AttackEpisode:
    """
    Converts a set of consecutive windows to an attack episode.

    :param windows: Set of consecutive windows
    :param time_step: Length of each window
    """
    # Sanity check: all windows are consecutive
    for i in range(1, len(windows)):
        assert windows[i - 1].start_time + 2 * time_step >= windows[i].start_time

    episode_start = windows[0].start_time - time_step
    episode_end = windows[-1].start_time + time_step
    all_alerts = []
    for window in windows:
        all_alerts += window.alerts

    mcat = all_alerts[0].mcat
    services = [a.service for a in all_alerts]
    return AttackEpisode(episode_start, episode_end, mcat, services, all_alerts)
