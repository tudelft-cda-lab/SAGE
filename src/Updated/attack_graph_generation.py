import os
import re
import json
from collections import defaultdict
import math

from src.Updated.common import most_frequent
from src.Updated.mappings.mappings import macro_inv, micro2macro, rev_smallmapping, micro

# Note: Kept as reference, should not be needed?

def loadmodel(modelfile):
    """Wrapper to load resulting model json file

     Keyword arguments:
     modelfile -- path to the json model file
    """

    # because users can provide unescaped new lines breaking json conventions
    # in the labels, we are removing them from the label fields
    with open(modelfile) as fh:
        data = fh.read()
    data = re.sub(r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data)

    data = data.replace('\n', '').replace(',,', ',')  # .replace(', ,', ',')#.replace('\t', ' ')

    data = re.sub(',+', ',', data)
    machine = json.loads(data)

    dfa = defaultdict(lambda: defaultdict(str))

    for edge in machine["edges"]:
        dfa[edge["source"]][edge["name"]] = (edge["target"], edge["appearances"])

    for entry in machine["nodes"]:
        dfa[str(entry['id'])]["type"] = "0"
        dfa[str(entry['id'])]["isred"] = int(entry['isred'])

    return (dfa, machine)


def traverse(dfa, sinks, sequence, statelist=False):
    """Wrapper to traverse a given model with a string

     Keyword arguments:
     dfa -- loaded model
     sequence -- space-separated string to accept/reject in dfa
    """
    # print(dfa)
    in_main_model = set()
    sinks = dict()  ## REMOVE IT!!!
    state = "0"
    stlst = ["0"]
    # print('This seq', sequence.split(" "))
    for event in sequence.split(" "):
        sym = event.split(":")[0]

        # print('curr symbol ', sym, 'state no.', dfa[state][sym])

        state = dfa[state][sym]
        isred = 0

        if state != "":
            isred = dfa[state[0]]["isred"]
        # print(state)
        # if state != "":
        if isred == 1:
            in_main_model.add(state[0])
        if state == "":
            # return -1 for low sev symbols
            sev = rev_smallmapping[sym.split('|')[0]]
            # print(sev)
            if len(str(sev)) >= 2:
                # print('high-sev sink found', sev)
                # print(stlst[-1], sinks[stlst[-1]], stlst)
                try:
                    state = sinks[stlst[-1]][sym][0]
                except:
                    # print('didnt work for', sequence, 'done so far:', stlst)
                    state = '-1'
            else:
                state = '-1'
            # print("Must look in sinks")
            # print('prev symb: ', sym, 'and prev state no.', stlst[-1])
            # print('BUT this last state no in sink gives ', sinks[stlst[-1]][sym])
            # print('curr sym', sym)
            # print('previous state no.:', stlst[-1], 'results in sink id:', sinks[stlst[-1]][sym] )
            # if sinks[stlst[-1]][sym] == "":

            # print('prob')
            # print(sequence)
            # state = '-1'
            # else:
            #      state = sinks[stlst[-1]][sym][0]
            #
            # if not statelist:
            #        return dfa[state]["type"] == "1"
            # else:
            #        return (dfa[state]["type"] == "1", stlst)

        else:
            try:
                # print('weird place')
                # take target id, discard counts
                state = state[0]
            except IndexError:
                print("Out of alphabet: alternatives")

                stlst.append("-1")
                if not statelist:
                    return dfa[state]["type"] == "1"
                else:
                    return dfa[state]["type"] == "1", stlst
        stlst.append(state)

    if not statelist:
        return dfa[state]["type"] == "1"
    else:
        return dfa[state]["type"] == "1", stlst


def encode_sequences(path_to_traces, m, m2):
    # print(m2)
    traces = []
    sp = []
    orig = []
    with open(path_to_traces) as tf:
        lines = tf.readlines()[1:]
    # print(len(lines))

    for line in lines:
        if line == lines[-1]:
            spl = line.split(' ')
        else:
            spl = line[:-1].split(' ')

        line = ' '.join(spl[2:])
        # print(spl[2:])
        orig.append([x for x in spl[2:] if x != ''])
        traces.append(line)
    num_sink = 0
    total = 0
    state_traces = dict()
    for i, sample in enumerate(traces):
        # print(sample)
        r, s = traverse(m, m2, sample, statelist=True)
        s = [(x) for x in s]
        sp.append(s)
        state_traces[i] = s

        total += len(s)
        true = [1 if x == '-1' else 0 for x in s]

        num_sink += sum(true)

        print('encoded', sample, state_traces[i])
        assert (len(sample.split(' ')) + 1 == len(state_traces[i]))

    # print(len(traces), len(state_traces))
    print('traces in sink:', num_sink, 'total', total, 'percentage:',
          100 * (num_sink / float(total)))
    return (traces, state_traces)


def find_severe_states(traces, m, m2):
    med_states = set()
    sev_states = set()
    for i, sample in enumerate(traces):
        r, s = traverse(m, m2, sample, statelist=True)
        s = s[1:]
        sample = sample.split(' ')
        # print([(x,rev_smallmapping[x[0].split('|')[0]]) for x in zip(sample, s)])
        med = [int(state) for sym, state in zip(sample, s) if
               len(str(rev_smallmapping[sym.split('|')[0]])) == 2]
        med_states.update(med)
        # print(s)
        sev = [int(state) for sym, state in zip(sample, s) if
               len(str(rev_smallmapping[sym.split('|')[0]])) == 3]
        # print([(sym) for sym, state in zip(sample, s) if len(str(rev_smallmapping[sym.split('|')[0]])) == 3 ])
        sev_states.update(sev)
        # if not set(sev_states).isdisjoint(s):
        #    print(sample)
        #    print('--', s)
    # print(med_states)
    # print(sev_states)
    # print('med-sev traces')
    # for i,sample in enumerate(traces):
    med_states = med_states.difference(sev_states)

    #    r, s = traverse(m, m2, sample, statelist=True)
    #    s = [int(x) for x in s]
    #    #print(s)
    #    if not set(med_states).isdisjoint(s):
    #        print(sample)
    #        print('--', s)
    print('Total medium states', len(med_states))
    print('Total severe states', len(sev_states))
    return (med_states, sev_states)


## collecting sub-behaviors back into the same trace -- condensed_data is the new object to deal with
def make_condensed_data(alerts, keys, state_traces, med_states, sev_states):
    levelone = set()
    levelone_ben = set()
    condensed_data = dict()
    counter = -1
    for tid, (attacker, episodes) in enumerate(zip(keys, alerts)):

        if len(episodes) < 3:
            continue
        # print(' ------------- COUNTER ', counter, '------')
        counter += 1
        if '10.0.254' not in attacker:
            continue
        if ('147.75' in attacker or '69.172' in attacker):
            continue
        tr = [int(x) for x in state_traces[counter]]
        # print(counter)
        num_servs = [len(set((x[6]))) for x in episodes]
        max_servs = [most_frequent(x[6]) for x in episodes]
        # print(max_servs)

        if 0 in tr and (not set(tr).isdisjoint(sev_states) or not set(tr).isdisjoint(med_states)):
            levelone.add(tr[tr.index(0) + 1])

        # print([x[2] for x in episodes])
        # print(state_traces[counter])
        new_state = (state_traces[counter][1:])[::-1]

        # print(new_state, [x[2] for x in episodes])
        # also artifically add tiny delay so all events are not exactly at the same time.
        # print(len(episodes), new_state, max_servs)
        times = [(x[0], x[1], x[2], int(new_state[i]), max_servs[i]) for i, x in
                 enumerate(episodes)]  # start time, endtime, episode mas, state ID

        step1 = attacker.split('->')
        step1_0 = step1[0].split('-')[0]
        step1_1 = step1[0].split('-')[1]
        step2 = step1[-1].split('-')[0]
        real_attacker = '->'.join([step1_0 + '-' + step1_1, step2])
        real_attacker_inv = '->'.join([step1_0 + '-' + step2, step1_1])
        # print(real_attacker)
        INV = False
        if '10.0.254' in step2:
            INV = True

        if real_attacker not in condensed_data.keys() and real_attacker_inv not in condensed_data.keys():
            if INV:
                condensed_data[real_attacker_inv] = []
            else:
                condensed_data[real_attacker] = []
        if INV:
            condensed_data[real_attacker_inv].extend(times)
            condensed_data[real_attacker_inv].sort(
                key=lambda tup: tup[0])  # sorts in place based on starting times
        else:
            condensed_data[real_attacker].extend(times)
            condensed_data[real_attacker].sort(
                key=lambda tup: tup[0])  # sorts in place based on starting times

    # print(len(condensed_data), counter)
    # print([c for c in condensed_data.values()][:5])

    # print('High-severity objective states', levelone, len(levelone))
    return condensed_data


def make_state_groups(condensed_data, datafile):
    state_groups = {
    }
    all_states = set()
    gcols = ['lemonchiffon', 'gold', 'khaki', 'darkkhaki', 'beige', 'goldenrod', 'wheat',
             'papayawhip', 'orange', 'oldlace', 'bisque']
    for att, episodes in condensed_data.items():
        # print([(x[2],x[3]) for x in episodes])

        state = [(x[2], x[3]) for x in episodes]
        all_states.update([x[3] for x in episodes])
        ## Sanity check
        '''for s in serv:
            FOUND= False
            for group,ser in ser_groups.items():
                if s in ser:
                    #print(s, '--', group)
                    FOUND= True
                    break
            if not FOUND:
                print('--- not found', s)'''

        for i, st in enumerate(state):
            # print(state[i])
            macro = micro2macro[micro[st[0]]].split('.')[1]

            if st[1] == -1 or st[1] == 0:  # state[i] == -1 or state[i] == 0:
                continue
            if macro not in state_groups.keys():
                state_groups[macro] = set()

            state_groups[macro].add(st[1])

    # state_groups['ACTIVE_RECON'] = state_groups['ACTIVE_RECON'].difference(state_groups['PRIVLEDGE_ESC'])
    # state_groups['PASSIVE_RECON'] = state_groups['PASSIVE_RECON'].difference(state_groups['PRIVLEDGE_ESC'])

    # print([(x) for x in state_groups.values()])
    # print((all_states))
    model = open(datafile + ".ff.final.dot", 'r')
    lines = model.readlines()
    model.close()
    written = []
    outlines = []
    outlines.append('digraph modifiedDFA {\n')
    for gid, (group, states) in enumerate(state_groups.items()):
        print(group)
        outlines.append('subgraph cluster_' + group + ' {\n')
        outlines.append('style=filled;\n')
        outlines.append('color=' + gcols[gid] + ';\n')
        outlines.append('label = "' + group + '";\n')
        for i, line in enumerate(lines):
            pattern = '\D+(\d+)\s\[\slabel="\d.*'
            SEARCH = re.match(pattern, line)
            if SEARCH:

                matched = int(SEARCH.group(1))
                # print(matched)
                if matched in states:
                    c = i
                    while '];' not in lines[c]:
                        # print(lines[c])
                        outlines.append(lines[c])
                        written.append(c)
                        c += 1
                    # print(lines[c])
                    outlines.append(lines[c])
                    written.append(c)
                elif matched not in all_states and group == 'ACTIVE_RECON':
                    if matched != 0:
                        c = i
                        while '];' not in lines[c]:
                            # print(lines[c])
                            outlines.append(lines[c])
                            written.append(c)
                            c += 1
                        # print(lines[c])
                        outlines.append(lines[c])
                        written.append(c)
                        state_groups['ACTIVE_RECON'].add(matched)
                    print('ERROR: manually handled', matched, ' in ACTIVE_RECON')
            # 0 -> 1 [label=
            # pattern2 = '\D+(\d+)\s->\s(\d+)\s\[label=.*'
            # SEARCH = re.match(pattern2, line)
            # if SEARCH:
            #     matched = int(SEARCH.group(1))
            #     print(line)
            #     if matched in states:
            #         c = i
            #         while '];' not in lines[c]:
            #             #print(lines[c])
            #             outlines.append(lines[c])
            #             written.append(c)
            #             c += 1
            #         #print(lines[c])
            #         outlines.append(lines[c])
            #         written.append(c)
        outlines.append('}\n')
        # break

    for i, line in enumerate(lines):
        if i < 2:
            continue
        if i not in written:
            outlines.append(line)
    # outlines.append('}\n')

    outfile = open('spdfa-clustered-' + datafile + '-dfa.dot', 'w')
    for line in outlines:
        outfile.write(line)
    outfile.close()

    outfile = 'spdfa-clustered-' + datafile
    os.system("dot -Tpng " + outfile + "-dfa.dot -o " + outfile + "-dfa.png")
    return state_groups


def make_av_data(condensed_data):
    ## Experiment: attack graph for one victim w.r.t time
    condensed_v_data = dict()
    for attacker, episodes in condensed_data.items():
        team = attacker.split('-')[0]
        victim = attacker.split('->')[1]
        tv = team + '-' + victim
        # print(tv)
        if tv not in condensed_v_data.keys():
            condensed_v_data[tv] = []
        condensed_v_data[tv].extend(episodes)
        condensed_v_data[tv] = sorted(condensed_v_data[tv], key=lambda item: item[0])
    condensed_v_data = {k: v for k, v in sorted(condensed_v_data.items(),
                                                key=lambda item: len([x[0] for x in item[1]]))}
    # print([(k,len([x[0] for x in v])) for k,v in condensed_v_data.items()])
    print('victims', (set([x.split('-')[-1] for x in condensed_v_data.keys()])))

    condensed_a_data = dict()
    for attacker, episodes in condensed_data.items():
        team = attacker.split('-')[0]
        victim = (attacker.split('->')[0]).split('-')[1]
        tv = team + '-' + victim
        # print(tv)
        if tv not in condensed_a_data.keys():
            condensed_a_data[tv] = []

        condensed_a_data[tv].extend(episodes)
        condensed_a_data[tv] = sorted(condensed_a_data[tv], key=lambda item: item[0])
        # print(len(condensed_a_data[tv]))
    # condensed_a_data = {k: v for k, v in sorted(condensed_a_data.items(), key=lambda item: item[1][0][0])}
    # print([(k,[x[0] for x in v]) for k,v in condensed_a_data.items()])
    print('attackers', (set([x.split('-')[1] for x in condensed_a_data.keys()])))
    return (condensed_a_data, condensed_v_data)


## Per-objective attack graph for dot: 14 Nov (final attack graph)
def make_AG(condensed_v_data, condensed_data, state_groups, datafile, expname):
    tcols = {
        't0': 'maroon',
        't1': 'orange',
        't2': 'darkgreen',
        't3': 'blue',
        't4': 'magenta',
        't5': 'purple',
        't6': 'brown',
        't7': 'tomato',
        't8': 'turquoise',
        't9': 'skyblue',
    }
    SAVE = True
    if SAVE:
        try:
            # if path.exists('AGs'):
            #    shutil.rmtree('AGs')
            dirname = expname + 'AGs'
            os.mkdir(dirname)
        except:
            print("Can't cerate directory here")
        else:
            print("Successfully created directory for AGs")

    # tcols = {'t0': 'saddlebrown'}
    # int_victim = []#['10.128.0.205']#['10.0.1.40', '10.0.1.41','10.0.1.42','10.0.1.43','10.0.1.44' ]

    shapes = ['oval', 'oval', 'oval', 'box', 'box', 'box', 'box', 'hexagon', 'hexagon', 'hexagon',
              'hexagon', 'hexagon']
    ser_total = dict()
    simple = dict()
    for intvictim in list(condensed_v_data.keys()):
        int_victim = intvictim.split('-')[1]
        # team=intvictim.split('-')[0]
        print('!!!_-------', int_victim)
        attacks = []
        A_lab, S_lab, stimes = [], [], []
        collective = dict()
        for att, episodes in condensed_data.items():
            service_theme = []
            this_times = []
            # print(len(episodes))
            # print([(x[2],x[3]) for x in episodes])
            for ep in episodes:

                time = math.ceil(ep[0] / 1.0)
                encode = [group for group, sts in state_groups.items() if ep[3] in sts]
                cat = -1
                if len(encode) == 0:
                    # continue
                    cat = micro[ep[2]].split('.')[1]
                    stateID = '|Sink' if len(str(ep[2])) == 1 else '|Sink'
                else:
                    cat = str(encode[
                                  0])  # str(encode[0]) if 'RECON' in encode[0] else str(encode[0])+'|'+str(ep[3])
                    stateID = '' if 'RECON' in encode[0] else '|' + str(ep[3])

                sorting = None
                try:
                    short = cat  # .split('|')[0]
                    sorting = macro_inv['MacroAttackStage.' + short]
                except:
                    sorting = -1
                # A_lab.append((sorting, cat))
                this_times.append(time)
                stimes.append(time)
                servtheme = str(micro[ep[2]].split('.')[1]) + '|' + str(ep[4]) + str(stateID)
                service_theme.append(servtheme)
                if len(str(ep[2])) == 3:
                    attacks.append(servtheme)
                S_lab.append((ep[2], servtheme))
            # print(service_theme)

            # A_lab = list(set(A_lab))
            S_lab = list(set(S_lab))

            # A_lab = sorted(A_lab, key=lambda x: x[0])

            S_lab = sorted(S_lab, key=lambda x: macro_inv[micro2macro[micro[x[0]]]])

            stimes = sorted(list(set(stimes)))

            # alab = [x[1] for x in A_lab]
            slab = [x[1] for x in S_lab]

            collective[att] = (service_theme, this_times)
        attacks = list(set(attacks))
        # Experiment 1: state IDs are not important. Attack graph should show all mas+service
        attacks = [x.split('|')[0] + '|' + x.split('|')[1] for x in attacks]
        # Experiment 2: state IDs and service are not important. Attack graph should show all mas
        # attacks = [x.split('|')[0] for x in attacks]
        attacks = list(set(attacks))
        # print(attacks)
        # path_info = dict()
        # print(len(set(slab)))
        # print(collective.keys())
        # print([(k,len(x[0])) for k,x in collective.items()])
        # print(collective['t1-10.0.254.202'])
        for attack in attacks:  # , 'DATA_DELIVERY|cslistener|27', 'DATA_EXFILTRATION|http|13']:# , , 'DATA_DESTRUCTION|us-cli|955', 'RESOURCE_HIJACKING|http|14']:

            # if attack not in path_info.keys():
            #    path_info[attack] = {'t0': [], 't1': [], 't2': [], 't3': [], 't4': [], 't5': []}

            # if obj_ser not in ser_total.keys():
            #    ser_total[obj_ser] = set()
            collect = dict()
            event_set = set()
            time_set = set()
            team_level = dict()
            sseen = []
            nodes = set()
            vertices, edges = 0, 0
            for att, episodes in condensed_data.items():
                # print(att)
                team = att.split('-')[0]
                # print([(x[3],x[0]) for x in episodes])
                event = []
                times = []
                # print(att)

                for ep in episodes:
                    time = round(ep[0] / 1.0)
                    encode = [group for group, sts in state_groups.items() if ep[3] in sts]
                    cat = -1
                    if len(encode) == 0:
                        # continue
                        cat = micro[ep[2]].split('.')[1]
                        stateID = '|Sink' if len(str(ep[2])) == 1 else '|Sink'
                    else:
                        cat = str(encode[
                                      0])  # str(encode[0]) if 'RECON' in encode[0] else str(encode[0])+'|'+str(ep[3])
                        stateID = '' if 'RECON' in encode[0] else '|' + str(ep[3])
                        # sorting= None
                        # try:
                        #    short = cat#.split('|')[0]
                        #    sorting = macro_inv['MacroAttackStage.'+short]
                        # except:
                        #    sorting =  -1
                        # stimes.append(time)

                    servtheme = str(micro[ep[2]].split('.')[1]) + '|' + str(ep[4]) + str(stateID)
                    times.append(time)
                    event.append(servtheme)

                    # if len(str(ep[2])) ==3:
                    #    attacks.append(servtheme)
                    # S_lab.append((ep[2], servtheme))
                # print(times)
                if not sum([True if attack in x else False for x in event]):
                    continue
                if int_victim not in att:
                    continue
                # print('-------!!!!', attack)
                # obj_ser = ser_inv[attack.split('|')[1]][0]
                # print('-------!!!SERVICE', attack.split('|')[1])
                # print([x for x in event])
                # print([x for x in times])
                event_set = set(event_set)
                time_set = set(time_set)

                event_set.update(event)
                time_set.update(times)

                event_set = sorted(event_set, key=lambda x: macro_inv[
                    micro2macro['MicroAttackStage.' + x.split('|')[0]]])
                time_set = sorted(time_set)

                data = [(x, y) for x, y in zip(event, times)]
                # cuts = [i for i in range(len(event)-1) if (len(str(micro_inv['MicroAttackStage.'+event[i].split('|')[0]])) > \
                #                                           len(str(micro_inv['MicroAttackStage.'+event[i+1].split('|')[0]]))) ]#
                # print('+++++', cuts)

                lists = []
                l = []

                # for i,d in enumerate(data):
                #     if i in cuts:
                #         l.append(d)
                #         if len(l) <= 1: ## If only a single node, reject
                #             l = []
                #             continue
                #
                #         if attack in l[-1][0]:
                #             sseen.append(d[0])
                #             lists.append(l)
                #         l = []
                #
                #         continue
                #     l.append(d)
                # if len(l) > 1 and attack in l[-1][0]:
                #     sseen.append(l[-1][0])
                #     lists.append(l)
                for d in data:
                    if attack in d[0]:
                        l.append(d)
                        if len(l) <= 1:  ## If only a single node, reject
                            l = []
                            continue
                        # print(len(l))
                        lists.append(l)
                        l = []
                        sseen.append(d[0])
                        continue
                    l.append(d)
                # print(lists)
                # print([[y[0] for y in x] for x in lists])
                if team not in team_level.keys():
                    team_level[team] = []
                team_level[team].extend(lists)
                # team_level[team] = sorted(team_level[team], key=lambda item: item[1])
            # print(sseen)
            # print('elements in graph', team_level.keys(), sum([len(x) for x in team_level.values()]))

            if sum([len(x) for x in team_level.values()]) == 0:
                continue

            name = attack.replace('|', '').replace('_', '').replace('-', '').replace('(',
                                                                                     '').replace(
                ')', '')
            lines = []
            lines.append((0, 'digraph ' + name + ' {'))
            lines.append((0, 'rankdir="BT";'))
            lines.append(
                (0, '"' + attack + '" [shape=doubleoctagon, style=filled, fillcolor=salmon];'))
            lines.append((0, '{ rank = max; "' + attack + '"}'))
            for s in list(set(sseen)):
                lines.append((0, '"' + s + '" -> "' + attack + '"'))
                # print(s, s.split('|')[1], ser_inv[s.split('|')[1]][0])

                # o = ser_inv[s.split('|')[1]][0]
                # if o not in ser_total.keys():
                #    ser_total[o] = set()
                # ser_total[o].add(s)
            for s in list(set(sseen)):
                lines.append((0, '"' + s + '" [style=filled, fillcolor= salmon]'))
            # print('-------!!!numObjs', set(sseen))

            samerank = '{ rank=same; "' + '" "'.join(sseen)
            samerank += '"}'
            lines.append((0, samerank))

            for k, vs in team_level.items():
                for v in vs:
                    # if v[0][1] == 89141:
                    #    continue
                    nodes.update([x[0] for x in v])

            for k, vs in team_level.items():
                ones = [''.join([y[0] for y in x]) for x in vs]
                # print(ones)
                unique = len(set(ones))
                # print(unique)
                # print('team', k, 'total paths', len(vs), 'unique paths', unique, 'longest path:', max([len(x) for x in vs]), \
                #     'shortest path:', min([len(x) for x in vs]))

                # path_info[attack][k].append((len(vs), unique, max([len(x) for x in vs]), min([len(x) for x in vs])))
                for v in vs:
                    # print(v[1])
                    # if v[0][1] == 89141:
                    #    continue

                    color = tcols[k]
                    bi = zip(v, v[1:])
                    for vid, (one, two) in enumerate(bi):

                        if vid == 0:
                            if 'Sink' in one[0]:
                                lines.append((0, '"' + one[
                                    0] + '" [style="dotted,filled", fillcolor= yellow]'))
                            else:
                                lines.append(
                                    (0, '"' + one[0] + '" [style=filled, fillcolor= yellow]'))
                        else:
                            if 'Sink' in one[0]:
                                line = [x[1] for x in lines]

                                partial = '"' + one[0] + '" [style="dotted'
                                # print(line)
                                # print('@@@@', partial)
                                if not sum([True if partial in x else False for x in line]):
                                    lines.append((0, partial + '"]'))
                            elif 'Sink' in two[0]:
                                line = [x[1] for x in lines]
                                partial = '"' + two[0] + '" [style="dotted'
                                # print(line)
                                # print('@@@@', partial)
                                if not sum([True if partial in x else False for x in line]):
                                    lines.append((0, partial + '"]'))
                                # lines.append((0,'"'+two[0]+'" [style="dotted"]'))
                        # edges += 1
                        lines.append((one[1], '"' + one[0] + '"' + ' -> ' + '"' + two[
                            0] + '"' + ' [ label=' + str(
                            one[1]) + ']' + '[ color=' + color + ']'))  #
            # lines = sorted(lines, key=lambda item: item[0], reverse=True)
            # print(lines)
            # print(nodes)
            for node in nodes:
                # vertices += 1
                mas = node.split('|')[0]
                mas = macro_inv[micro2macro['MicroAttackStage.' + mas]]
                shape = shapes[mas]
                lines.append((0, '"' + node + '" [shape=' + shape + ']'))
            lines.append((1000, '}'))

            for l in lines:
                if '->' in l[1]:
                    edges += 1
                elif 'shape=' in l[1]:
                    vertices += 1

            simple[int_victim + '-' + name] = (vertices, edges)
            # print('# vert', vertices, '# edges: ', edges,  'simplicity', vertices/float(edges))
            # print('file')
            if SAVE:
                v = int_victim  # .replace('.','')
                f = open(
                    dirname + '/' + datafile + '-attack-graph-for-victim-' + v + '-' + name + '.dot',
                    'w')
                for l in lines:
                    # print(l[1])
                    f.write(l[1])
                    f.write('\n')
                f.close()
                out_f_name = datafile + '-attack-graph-for-victim-' + v + '-' + name
                os.system(
                    "dot -Tpng " + dirname + '/' + out_f_name + ".dot -o " + dirname + '/' + out_f_name + ".png")
                # print('~~~~~~~~~~~~~~~~~~~~saved')
            print('----')
        # print('total high-sev states:', len(path_info))
        # path_info = dict(sorted(path_info.items(), key=lambda kv: kv[0]))
        # for k,v in path_info.items():
        #    print(k)
        #    for t,val in v.items():
        #       print(t, val)
    # for k,v in ser_total.items():
    #    print(k, len(v), set([x.split('|')[0] for x in v]))
