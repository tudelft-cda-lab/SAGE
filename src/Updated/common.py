import pickle


def inverse_map(m):
    """
    Changes a map, converting keys to values and values to keys.
    Assumes each value is unique: in case of duplicate values, the key can be overwritten
    :param m: Map to invert
    """
    return {v: k for k, v in m.items()}


def inverse_map_aggregate(m):
    """
    Changes a map, converting keys to values and values to keys.

    In the result, each value maps to a list of all keys containing the value.
    :param m: Map to invert
    """
    res = {}
    for key, value in m.items():
        if value in res:
            res[value].append(key)
        else:
            res[value] = [key]
    return res


def save_pkl(data, filename):
    """
    Saves data to a pkl file.

    Note: Don't share picked data: https://docs.python.org/3/library/pickle.html
      Only read data you trust/know
    """
    file = open(filename, "wb")
    pickle.dump(data, file)
    file.close()


def read_pkl(filename):
    """
    Reads data from a pkl file

    Note: Don't share picked data: https://docs.python.org/3/library/pickle.html
      Only read data you trust/know
    """
    file = open(filename, "rb")
    res = pickle.load(file)
    file.close()
    return res
