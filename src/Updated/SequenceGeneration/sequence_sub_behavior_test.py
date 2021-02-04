from src.Base.episodes import host_episode_sequences, break_into_subbehaviors
from src.Updated.SequenceGeneration import get_host_episode_sequences, \
    get_host_sub_behaviors
from src.Updated.SequenceGeneration import read_pkl, save_pkl
from src.Updated.SequenceGeneration import TeamAttackEpisodes


def setup():
    episodes_base, team_times = read_pkl("test_data/base_episodes.pkl")
    episodes_update: TeamAttackEpisodes = read_pkl("test_data/update_episodes.pkl")

    assert len(episodes_base[0]) == len(episodes_update[0])
    print("Loaded")

    base_sequences = host_episode_sequences(episodes_base)
    update_sequences = get_host_episode_sequences(episodes_update)
    print("Got sequences")

    save_pkl(base_sequences, "./test_data/base_sequences.pkl")
    save_pkl(update_sequences, "./test_data/update_sequences.pkl")


def main():
    base_sequences = read_pkl("./test_data/base_sequences.pkl")
    update_sequences = read_pkl("./test_data/update_sequences.pkl")
    print("Loaded")

    base_sub_sequences, base_keys = break_into_subbehaviors(base_sequences)
    update_sub_sequences, update_keys = get_host_sub_behaviors(update_sequences)

    # Note: '10.0.0.20', '10.0.1.5' is now extra (see previous tests) -> this is removed from
    #  the updated set
    idx = update_keys.index('t0-10.0.0.20->10.0.1.5-0')
    del update_sub_sequences[idx]
    del update_keys[idx]

    # 't0-10.0.0.20->10.0.1.5-0'
    assert len(base_sub_sequences) == len(update_sub_sequences)
    assert len(base_keys) == len(update_keys)

    for i in range(len(base_keys)):
        assert base_keys[i] == update_keys[i]

        base_seq = base_sub_sequences[i]
        update_seq = update_sub_sequences[i]

        if base_keys[i] == 't0-10.0.254.202->10.0.0.22-2':
            # Note: Remove last part -> extra episode (see previous test)
            update_seq = update_seq[:-1]

        assert len(base_seq) == len(update_seq)
        for j in range(len(base_seq)):
            base = base_seq[j]
            update = update_seq[j]

            assert base[7] == update[1]
            assert base[0] == update[0].start_time
            assert base[1] == update[0].end_time
            assert base[2] == update[0].mcat
            assert base[6] == update[0].services


if __name__ == '__main__':
    # setup()
    main()
