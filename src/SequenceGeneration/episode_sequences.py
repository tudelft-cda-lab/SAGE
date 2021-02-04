from typing import Tuple, List, Dict

from src.SequenceGeneration.episodes_updated import TeamAttackEpisodes, AttackEpisode

# TeamAttackEpisodes = Dict[int, Dict[Tuple, List[AttackEpisode]]]

HostEpisode = Tuple[AttackEpisode, str]

HostData = Dict[str, List[List[HostEpisode]]]


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
            perp, target = attacker

            att = f"t{team_id}-{perp}"
            if att not in host_data.keys():
                host_data[att] = []
            ext = [(x, target) for x in episodes]

            host_data[att].append(ext)

    # Sort by episode sequence start time
    for attacker in host_data:
        host_data[attacker].sort(key=lambda tup: tup[0][0].start_time)

    print(len(host_data))
    return host_data


SubBehaviors = Tuple[List[List[HostEpisode]], List[str]]


def get_host_sub_behaviors(data: HostData, min_seq_length=4) -> SubBehaviors:
    res = []
    keys = []

    for tid, (attacker, target) in enumerate(data.items()):
        # Attacker is t0->1.2.3.4

        print('----- Sequence # ', tid, ' -----')

        for episodes in target:
            mcats = [he[0].mcat for he in episodes]

            # Skip this
            if len(episodes) < 2:
                continue

            target_ip = episodes[0][1]
            if len(episodes) < min_seq_length:
                # Add full list as sequence
                res.append(episodes)
                keys.append(f"{attacker}->{target_ip}-0")
                continue

            # Split mcats based on decreasing value
            splits = [i for i in range(1, len(mcats)) if
                      len(str(mcats[i])) < len(str(mcats[i - 1]))]
            splits = [0] + splits + [len(mcats)]

            sub_sequence_count = 0

            for i in range(len(splits) - 1):
                start = splits[i]
                end = splits[i + 1]
                sequence = episodes[start:end]
                if len(sequence) < 2:
                    print(f"Discarding: {mcats[start:end]} {start} {end} {len(episodes)}")
                    continue
                res.append(sequence)
                keys.append(f"{attacker}->{target_ip}-{sub_sequence_count}")
                sub_sequence_count += 1

    return res, keys
