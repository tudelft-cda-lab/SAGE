from typing import Tuple, List, Dict

from src.SequenceGeneration.episodes_updated import TeamAttackEpisodes, AttackEpisode

# TeamAttackEpisodes = Dict[int, Dict[Tuple, List[AttackEpisode]]]

HostData = Dict[str, List[List[Tuple[AttackEpisode, str]]]]


def get_host_episode_sequences(episodes: TeamAttackEpisodes) -> HostData:
    host_data: HostData = {}

    for team_id, team_data in episodes.items():
        print(f"--------- Team {team_id} ---------")
        print(len(set([x[0] for x in team_data.keys()])))

        for attacker, episodes in team_data.items():
            # Note: Why filter short episodes
            if len(episodes) < 2:
                print(f"Skipping {attacker}")
                continue
            perp, vic = attacker

            att = f"t{team_id}-{perp}"
            if att not in host_data.keys():
                host_data[att] = []
            ext = [(x, vic) for x in episodes]

            host_data[att].append(ext)

    # Sort by episode sequence start time
    for attacker in host_data:
        host_data[attacker].sort(key=lambda tup: tup[0][0].start_time)

    print(len(host_data))
    return host_data


def get_host_sub_behaviors(data: HostData):
    pass
