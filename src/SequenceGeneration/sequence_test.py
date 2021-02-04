import pickle

from src.SequenceGeneration.episode_sequences import get_host_episode_sequences
from src.SequenceGeneration.episodes import aggregate_into_episodes, host_episode_sequences
from src.SequenceGeneration.episodes_test import read_pkl, save_pkl
from src.SequenceGeneration.load import *
from src.SequenceGeneration.episodes_updated import get_attack_episodes, TeamAttackEpisodes


def setup():
    data_base, team_labels = read_pkl("test_data/base.pkl")
    data_update: LoadedData = read_pkl("test_data/update.pkl")
    print("Loaded data")

    # TODO: Find out why the first alert is removed in the original code
    data_update[0][0] = data_update[0][0][1:]
    assert len(data_base[0]) == len(data_update[0][0])

    print("Aggregating base")
    episodes_base, team_times = aggregate_into_episodes(data_base, team_labels, step=150)
    print("Aggregating update")
    episodes_update = get_attack_episodes(data_update, time_step=150)
    print("Done aggregating")

    save_pkl((episodes_base, team_times), "test_data/base_episodes.pkl")
    save_pkl(episodes_update, "test_data/update_episodes.pkl")


def main():
    episodes_base, team_times = read_pkl("test_data/base_episodes.pkl")
    episodes_update: TeamAttackEpisodes = read_pkl("test_data/update_episodes.pkl")

    assert len(episodes_base[0]) == len(episodes_update[0])
    print("Loaded")

    base_sequences = host_episode_sequences(episodes_base)
    update_sequences = get_host_episode_sequences(episodes_update)

    assert len(base_sequences) == len(update_sequences)
    for host, seq in base_sequences.items():
        if '10.0.0.20' in host:
            # Note: See episodes_test -> this one should have a non-filtered episode sequence
            continue
        assert host in update_sequences
        assert len(seq) == len(update_sequences[host])
        for i in range(len(seq)):
            base = seq[i]
            update = update_sequences[host][i]
            for j, b in enumerate(base):
                assert b[0] == update[j][0].start_time
                assert b[1] == update[j][0].end_time
                assert b[2] == update[j][0].mcat
                assert b[6] == update[j][0].services
                assert b[7] == update[j][1]

            # assert

    print("Done")


if __name__ == '__main__':
    # setup()
    main()
