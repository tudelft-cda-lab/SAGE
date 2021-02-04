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


def most_frequent(serv):
    """
    Finds the most frequent value in a collection
    """
    # TODO: does this work?
    return max(set(serv), key=serv.count)
