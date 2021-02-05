import subprocess
from typing import List

import graphviz
from IPython.display import Image, display

from src.Updated.SequenceGeneration.sequences import SubBehaviors, HostEpisode
from src.Updated.mappings.mappings import ser_inv, small_mapping

FLEXFRINGE_PATH = "C:\\Users\\anadeem1\\Downloads\\dfasat\\cmake-build-release\\flexfringe.exe"
DEFAULT_INI = "C:\\Users\\Geert\\Desktop\\Thesis\\AD-Attack-Graph\\src\\data\\s_pdfa.ini"


def most_frequent(serv):
    """
    Finds the most frequent value in a collection
    """
    # TODO: does this work?
    return max(set(serv), key=serv.count)


#                       alerts                  keys
# SubBehaviors = Tuple[List[List[HostEpisode]], List[str]]
def construct_traces(sub_sequences: SubBehaviors, filename: str) -> None:
    sequences = sub_sequences[0]
    keys = sub_sequences[1]

    # Count number of unique symbols -> used for writing the header
    unique_symbols = set()
    traces: List[str] = []

    def sequence_to_symbols(seq: List[HostEpisode]) -> List[str]:
        res = []
        for (ep, target_ip) in seq:
            mcat = small_mapping[ep.mcat]
            service = ser_inv[most_frequent(ep.services)][0]

            res.append(f"{mcat}|{service}")

        return res

    for i in range(len(sequences)):
        sequence = sequences[i]
        key = keys[i]

        # Skip short sequences
        if len(sequence) < 3:
            continue

        sequence_symbols = sequence_to_symbols(sequence)
        unique_symbols.update(sequence_symbols)

        symbols_str = " ".join(reversed(sequence_symbols))
        traces.append(f"1 {len(sequence_symbols)} {symbols_str}")

    file = open(filename, "w+")
    file.write(f"{len(traces)} {len(unique_symbols)}\n")
    file.write("\n".join(traces))
    file.close()


## 27 Aug 2020: Generating traces for flexfringe
def generate_traces(alerts, keys, datafile, test_ratio=0.0):
    victims = alerts
    al_services = [[most_frequent(y[6]) for y in x] for x in victims]
    print('all unique servcies')
    print(set([item for sublist in al_services for item in sublist]))
    print('---- end')

    count_lines = 0
    count_cats = set()

    f = open(datafile, 'w')  # 'C:\\Users\\anadeem1\\Downloads\\dfasat\\data\\test.txt', 'w')
    lengths = []
    lines = []
    for i, episodes in enumerate(victims):
        # print(episodes)
        num_behav = keys[i].split('-')[-1]
        # print(keys[i], num_behav)
        if len(episodes) < 3:
            continue
        # lengths+= len(episodes)
        count_lines += 1
        mcats = [str(x[2]) for x in episodes]
        num_servs = [len(set((x[6]))) for x in episodes]
        max_servs = [ser_inv[most_frequent(x[6])][0] for x in episodes]
        stime = [x[0] for x in episodes]
        # print(stime)
        # print(' '.join(mcats))

        # multi = [str(c)+":"+str(n)+","+str(s) for (c,s,n) in zip(mcats,max_servs,num_servs)] # multivariate case
        multi = [str(small_mapping[int(c)]) + "|" + str(s) for (c, s, n, st) in
                 zip(mcats, max_servs, num_servs, stime)]  # merging mcat and serv into one
        # print(multi)
        for e in multi:
            feat = e.split(':')[0]
            count_cats.add(feat)
        multi.reverse()
        st = '1' + " " + str(len(mcats)) + ' ' + ' '.join(multi) + '\n'
        # f.write(st)
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()
    # print(lengths, lengths/float(count_lines))


## 2 sept 2020: Learning the model
def flexfringe(*args, **kwargs):
    """Wrapper to call the flexfringe binary

     Keyword arguments:
     position 0 -- input file with trace samples
     kwargs -- list of key=value arguments to pass as command line arguments
    """
    command = ["--help"]

    if (len(kwargs) >= 1):
        command = []
        for key in kwargs:
            command += ["--" + key + "=" + kwargs[key]]
    result = subprocess.run([
                                "C:\\Users\\Geert\\Desktop\\Thesis\\flexfringe\\flexfringe.exe", ] + command + [
                                args[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    print(result.returncode, result.stdout, result.stderr)

    try:
        with open("dfafinal.dot") as fh:
            return fh.read()
    except FileNotFoundError:
        pass

    return "No output file was generated."


def show(data):
    """Show a dot string as (inline-) PNG

      Keyword arguments:
      data -- string formated in graphviz dot language to visualize
    """
    if data == "":
        pass
    else:
        g = graphviz.Source(data, format="png")
        g.render()
        display(Image(g.render()))
