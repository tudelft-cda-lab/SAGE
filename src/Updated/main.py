import matplotlib as mpl
import matplotlib.style

from src.Updated.SequenceGeneration.episodes import get_attack_episodes
from src.Updated.SequenceGeneration.load import load_data
from src.Updated.SequenceGeneration.sequences import get_host_episode_sequences, \
    get_host_sub_behaviors, SubBehaviors
from src.Updated.common import save_pkl, read_pkl
from src.Updated.flexfringe import construct_traces

mpl.style.use('default')

# TODO: Re-write file

folder = "../data/cptc_18_full/"
expname = "test_1"
t = 1.0
w = 150
rev = "2018"

# saddr = 'C:\\Users\\anadeem1\\Downloads\\dfasat\\data\\'  # path_to_flexfringe installation
# outaddress = ""  # "C:\\Users\\anadeem1\\Downloads\\dfasat\\"
# path_to_ini = "C:\\Users\\anadeem1\\Downloads\\dfasat\\ini\\batch-likelihoodRIT.ini"

saddr = "C:\\Users\\Geert\\Desktop\\Thesis\\flexfringe\\flexfringe.exe"
outaddress = "C:\\Users\\Geert\\Desktop\\Thesis\\AD-Attack-Graph\\src\\out\\"
path_to_ini = "/src/data/s_pdfa.ini"

modelname = expname + '.txt'  # 'test-trace-uni-serGroup.txt'
datafile = expname + '.txt'  # 'trace-uni-serGroup.txt'

path_to_traces = datafile


def proces_data():
    parsed_data = load_data(folder, t, "CPTC'18")
    episodes = get_attack_episodes(parsed_data, time_step=w)
    host_sequences = get_host_episode_sequences(episodes)
    sub_sequences = get_host_sub_behaviors(host_sequences)

    save_pkl(sub_sequences, "./cptc_18_full_sub_sequences_filter_alter.pkl")


def load_sub_behaviors() -> SubBehaviors:
    return read_pkl("./cptc_18_full_sub_sequences_filter_alter.pkl")


def main():
    proces_data()
    data = load_sub_behaviors()
    print("Done parsing/mapping data")
    construct_traces(data, "./traces_cptc_18_full_filter_alter.txt")



# print('----- Reading alerts ----------')
# (unparse, team_labels) = load_data(folder, t, rev)  # t = minimal window for alert filtering
# plt = plot_histogram(unparse, team_labels)
# plt.savefig('data_histogram-' + expname + '.png')
# print('------ Converting to episodes ---------')
# team_episodes, _ = aggregate_into_episodes(unparse, team_labels, step=w)  # step = w
# print('---- Converting to episode sequences -----------')
# host_data = host_episode_sequences(team_episodes)
# print('----- breaking into sub-sequences and making traces----------')
# (alerts, keys) = break_into_subbehaviors(host_data)
# print("break")
# generate_traces(alerts, keys, datafile)

# print('------ Learning SPDFA ---------')
# # Learn S-PDFA
# flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")
#
# ## Copying files
# outfile = (outaddress + datafile)
# o = (outaddress + modelname)
# os.system("dot -Tpng " + outfile + ".ff.final.dot -o " + o + ".png")
# # files = [ datafile+'.ff.final.dot', datafile+'.ff.final.dot.json', datafile+'.ff.sinksfinal.json', datafile+'.ff.init_dfa.dot', datafile+'.ff.init_dfa.dot.json']
# # outfiles = [ modelname+'.ff.final.dot', modelname+'.ff.final.dot.json', modelname+'.ff.sinksfinal.json', modelname+'.ff.init_dfa.dot', modelname+'.ff.init_dfa.dot.json']
# # for (file,out) in zip(files,outfiles):
# #    copyfile(outaddress+file, outaddress+out)
#
# path_to_model = outaddress + modelname
#
# print('------ !! Special: Fixing syntax error in sinks files  ---------')
# with open(path_to_model + ".ff.sinksfinal.json", 'r') as file:
#     filedata = file.read()
# filedata = ''.join(filedata.rsplit(',', 1))
# with open(path_to_model + ".ff.sinksfinal.json", 'w') as file:
#     file.write(filedata)
#
# # with open(path_to_model+".ff.final.dot.json", 'r') as file:
# #     filedata = file.read()
# # filedata = ''.join(filedata.rsplit(',', 1))
# # with open(path_to_model+".ff.final.dot.json", 'w') as file:
# #     file.write(filedata)
#
# print('------ Loading and traversing SPDFA ---------')
# # Load S-PDFA
# m, data = loadmodel(path_to_model + ".ff.final.dot.json")
# m2, data2 = loadmodel(path_to_model + ".ff.sinksfinal.json")
#
# print('------- Encoding into state sequences --------')
# # Encoding traces into state sequences
# (traces, state_traces) = encode_sequences(path_to_traces, m, m2)
# (med_states, sev_states) = find_severe_states(traces, m, m2)
# condensed_data = make_condensed_data(alerts, keys, state_traces, med_states, sev_states)
#
# print('------- clustering state groups --------')
# state_groups = make_state_groups(condensed_data, modelname)
# (condensed_a_data, condensed_v_data) = make_av_data(condensed_data)
#
# print('------- Making alert-driven AGs--------')
# make_AG(condensed_v_data, condensed_data, state_groups, modelname, expname)

print('------- FIN -------')
## ----- main END ------

if __name__ == '__main__':
    main()
