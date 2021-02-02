import pickle

from src.SequenceGeneration.episodes import aggregate_into_episodes
from src.SequenceGeneration.load import *
from src.SequenceGeneration.load import _parse, _remove_duplicate, _load_data
from src.SequenceGeneration.episodes_updated import get_attack_episodes
from src.SequenceGeneration.load import read_file, _parse

FILE = "../data/cptc_18/suricata_alert_t2.json"
FOLDER = "../data/cptc_18/"


def save_pkl(data, filename):
    file = open(filename, "wb")
    pickle.dump(data, file)
    file.close()


def read_pkl(filename):
    file = open(filename, "rb")
    res = pickle.load(file)
    file.close()
    return res


def setup():
    data_base, team_labels = load_data(FOLDER, 1.0, "2018")
    data_update = _load_data(FOLDER, 1.0, "CPTC'18")

    save_pkl((data_base, team_labels), "./base.pkl")
    save_pkl(data_update, "./update.pkl")


def main():
    # data_base, team_labels = load_data(FOLDER, 1.0, "2018")
    # data_update = _load_data(FOLDER, 1.0, "CPTC'18")
    data_base, team_labels = read_pkl("./base.pkl")
    data_update: LoadedData = read_pkl("./update.pkl")
    print("Loaded data")

    # TODO: Find out why the first alert is removed in the original code
    data_update[0][0] = data_update[0][0][1:]
    assert len(data_base[0]) == len(data_update[0][0])

    print("Aggregating base")
    episodes_base, _ = aggregate_into_episodes(data_base, team_labels, step=150)
    print("Aggregating update")
    episodes_update = get_attack_episodes(data_update, time_step=150)
    print("Done aggregating")

    team_base = episodes_base[0]
    team_update = episodes_update[0]

    if len(team_base) != len(team_update):
        base_attackers = set(team_base.keys())
        updated_attackers = set(team_update.keys())
        diff_1 = updated_attackers - base_attackers
        diff_2 = base_attackers - updated_attackers

    for attacker, base in team_base.items():
        print(f"Testing attacker {attacker}")
        assert attacker in team_update
        update = team_update[attacker]
        assert len(base) == len(update)

        for i in range(len(base)):
            base_ep = base[i]
            update_ep = update[i]
            print(i)
            assert update_ep.start_time == base_ep[0]
            assert update_ep.end_time == base_ep[1]
            assert update_ep.mcat == base_ep[2]
            assert update_ep.services == base_ep[6]
        print(f"Attacker {attacker} is okay")

    print("done")


if __name__ == '__main__':
    # setup()
    main()

# ("10.0.0.20", "147.75.40.2")
# a = [(0, 150, 7, [1, 0], 0.5, 150, ['http']),
#      (900, 1200, 7, [0, 1, 0], 0.3, 300, ['http']),
#      (901, 1200, 21, [0, 1, 0], 0.3, 300, ['http']),
#      (2250, 2550, 7, [0, 1, 0], 0.3, 300, ['http']),
#      (2251, 2550, 21, [0, 1, 0], 0.3, 300, ['http']),
#      (29400, 29550, 7, [0, 1], 0.5, 150, ['http']),
#      (29401, 29550, 21, [0, 1], 0.5, 150, ['http'])]


# ('10.0.254.202', '10.0.0.11')
# [(1520, 1820, 4, [0, 58, 0], 19.3, 300, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http']),
#  (1521, 1820, 5, [2, 1, 0], 1.0, 300, ['unknown', 'unknown', 'ssh']),
#  (1522, 1670, 6, [9, 0], 4.5, 150, ['mysql', 'ms-sql-s', 'ncube-lm', 'postgresql', 'mysql', 'ncube-lm', 'ms-sql-s', 'ahsp', 'postgresql']),
#  (2570, 3020, 5, [0, 4, 2, 0], 1.5, 450, ['unknown', 'unknown', 'unknown', 'unknown', 'ssh', 'ssh']),
#  (2571, 2870, 6, [0, 9, 0], 3.0, 300, ['mysql', 'ncube-lm', 'ahsp', 'postgresql', 'ms-sql-s', 'mysql', 'ms-sql-s', 'postgresql', 'ncube-lm']),
#  (2720, 3020, 4, [0, 38, 0], 12.7, 300, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http']),
#  (3320, 3470, 4, [0, 4], 2.0, 150, ['http', 'http', 'http', 'http'])]

