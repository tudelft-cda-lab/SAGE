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

    base_attackers = set(team_base.keys())
    updated_attackers = set(team_update.keys())
    diff_1 = updated_attackers - base_attackers
    diff_2 = base_attackers - updated_attackers
    print(f"{len(base_attackers)} attackers in base, {len(updated_attackers)} attackers in update")
    print(f"{diff_1} in updated, not in base")
    print(f"{diff_2} in base, not in updated")

    for attacker, base in team_base.items():
        # if attacker in {('10.0.254.202', '10.0.0.22')}:
        #     continue
        update = team_update[attacker]
        # assert attacker in team_update
        # assert len(base) == len(update)
        #
        # for i in range(len(base)):
        #     base_ep = base[i]
        #     update_ep = update[i]
        #
        #     assert update_ep.start_time == base_ep[0]
        #     assert update_ep.end_time == base_ep[1]
        #     assert update_ep.mcat == base_ep[2]
        #     assert update_ep.services == base_ep[6]

        if len(base) != len(update):
            print(
                f"{attacker} -> different number of episodes: expected {len(base)}, got {len(update)}")
            continue

        for i in range(len(base)):
            base_ep = base[i]
            update_ep = update[i]
            # print(i)
            if update_ep.start_time != base_ep[0] or update_ep.end_time != base_ep[1] or \
                    update_ep.mcat != base_ep[2] or update_ep.services != base_ep[6]:
                print(f"{attacker} -> difference at index {i}")

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

# ('10.0.254.202', '10.0.0.176')
# [(1520, 2120, 5, [2, 2, 0, 1, 0], 1.0, 600, ['unknown', 'unknown', 'unknown', 'unknown', 'ssh']),
#  (1521, 1820, 6, [4, 5, 0], 3.0, 300, ['mysql', 'ms-sql-s', 'ncube-lm', 'postgresql', 'mysql', 'ncube-lm', 'ms-sql-s', 'ahsp', 'postgresql']),
#  (1820, 2120, 4, [0, 132, 0], 44.0, 300, ['etlservicemgr', 'etlservicemgr', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'etlservicemgr', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'etlservicemgr', 'etlservicemgr']),
#  (2570, 3170, 5, [0, 2, 1, 4, 0], 1.4, 600, ['unknown', 'unknown', 'ssh', 'unknown', 'unknown', 'unknown', 'unknown']),
#  (2571, 3170, 6, [0, 4, 0, 10, 0], 2.8, 600, ['mysql', 'ms-sql-s', 'postgresql', 'ncube-lm', 'mysql', 'mysql', 'ncube-lm', 'ncube-lm', 'ahsp', 'ahsp', 'postgresql', 'postgresql', 'ms-sql-s', 'ms-sql-s']),
#  (10220, 10520, 21, [0, 2, 0], 0.7, 300, ['http-alt', 'http-alt']),
#  (34070, 34220, 5, [0, 1], 0.5, 150, ['ssh'])]


# Note: Seems to be wrong: the issue lies with this attacker id, and the mcat 11
# ('10.0.254.202', '10.0.0.22')
# [(1521, 2121, 5, [2, 2, 2, 1, 0], 1.4, 600, ['cpdlc', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown', 'ssh']),
# (1522, 1971, 6, [8, 6, 4, 0], 4.5, 450, ['mysql', 'mysql', 'ms-sql-s', 'ms-sql-s', 'ncube-lm', 'ncube-lm', 'postgresql', 'postgresql', 'mysql', 'mysql', 'ncube-lm', 'ncube-lm', 'ms-sql-s', 'ms-sql-s', 'ahsp', 'ahsp', 'postgresql', 'postgresql']),
# (1671, 2271, 13, [0, 2, 4, 3, 0], 1.8, 600, ['imaps', 'pop3s', 'pop3s', 'pop3', 'imaps', 'imap', 'imaps', 'imaps', 'imap']),
# (1821, 2121, 4, [0, 58, 0], 19.3, 300, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http']),
# (2571, 3321, 5, [0, 2, 0, 4, 1, 0], 1.2, 750, ['unknown', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown', 'ssh']),
# (2572, 3171, 6, [0, 8, 0, 10, 0], 3.6, 600, ['mysql', 'mysql', 'ms-sql-s', 'ms-sql-s', 'postgresql', 'postgresql', 'ncube-lm', 'ncube-lm', 'mysql', 'mysql', 'ncube-lm', 'ncube-lm', 'ahsp', 'ahsp', 'postgresql', 'postgresql', 'ms-sql-s', 'ms-sql-s']),
# (2871, 3471, 13, [0, 2, 3, 4, 0], 1.8, 600, ['pop3s', 'imaps', 'imaps', 'pop3s', 'pop3', 'imap', 'imaps', 'imaps', 'imap']),
# (3021, 3471, 4, [0, 24, 34, 0], 14.5, 450, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http']),
# (28821, 29121, 4, [0, 58, 0], 19.3, 300, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http']),
# (28822, 29121, 5, [0, 5, 0], 1.7, 300, ['unknown', 'unknown', 'ssh', 'unknown', 'unknown']),
# (28823, 29121, 6, [0, 8, 0], 2.7, 300, ['mysql', 'mysql', 'ncube-lm', 'ncube-lm', 'postgresql', 'postgresql', 'ms-sql-s', 'ms-sql-s']),
# (30021, 30321, 11, [0, 1, 0], 0.3, 300, ['smtp'])] : 12 items
# Note: I would expect: (31071, 31371, 11, [0, 2, 2], ???, 300, ['smtp', 'smtp', 'smtp', 'smtp'])

# Note: current issues
# ('10.0.254.202', '10.0.0.22') -> different number of episodes: expected 12, got 13 -> see above
# ('10.0.0.20', '10.0.1.5') -> different number of episodes: expected 1, got 2 -> see below

# ('10.0.0.20', '10.0.1.5')
# [(17721, 17871, 4, [12, 0], 6.0, 150, ['http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http', 'http'])]
# Expected another episode:
# (29271, 29571, 21, [0, 2]?, ???, 300, ['http', 'http'])
