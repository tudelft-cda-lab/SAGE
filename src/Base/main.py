import sys

## ----- main ------
### Load port numbers and services (from Andrea Corsini)
from src.Base.load import *
from src.Base.mappings import *
from src.Base.flexfringe import *
from src.Base.graph_generation import *
from src.Base.episodes import *
from src.Base.plot import *

if len(sys.argv) < 5:
    print(
        'USAGE: ag-gen.py {path/to/json/files} {experiment-name} {alert-filtering-window (def=1.0)} {alert-aggr-window (def=150)} {mode}')
    sys.exit()
folder = sys.argv[1]
expname = sys.argv[2]
t = float(sys.argv[3])
w = int(sys.argv[4])
rev = False
if len(sys.argv) >= 6:
    rev = sys.argv[5]

# saddr = 'C:\\Users\\anadeem1\\Downloads\\dfasat\\data\\' # path_to_flexfringe installation
# outaddress = ""#"C:\\Users\\anadeem1\\Downloads\\dfasat\\"
# path_to_ini = "C:\\Users\\anadeem1\\Downloads\\dfasat\\ini\\batch-likelihoodRIT.ini"

saddr = "C:\\Users\\Geert\\Desktop\\Thesis\\flexfringe\\flexfringe.exe"
outaddress = ""  # "C:\\Users\\anadeem1\\Downloads\\dfasat\\"
path_to_ini = "C:\\Users\\Geert\\Desktop\\Thesis\\AD-Attack-Graph\\src\\data\\s_pdfa.ini"

modelname = expname + '.txt'  # 'test-trace-uni-serGroup.txt'
datafile = expname + '.txt'  # 'trace-uni-serGroup.txt'

path_to_traces = datafile

port_services = load_IANA_mapping()

print('----- Reading alerts ----------')
(unparse, team_labels) = load_data(folder, t, rev)  # t = minimal window for alert filtering
plt = plot_histogram(unparse, team_labels)
plt.savefig('data_histogram-' + expname + '.png')
print('------ Converting to episodes ---------')
team_episodes, _ = aggregate_into_episodes(unparse, team_labels, step=w)  # step = w
print('---- Converting to episode sequences -----------')
host_data = host_episode_sequences(team_episodes)
print('----- breaking into sub-sequences and making traces----------')
(alerts, keys) = break_into_subbehaviors(host_data)
generate_traces(alerts, keys, datafile)

print('------ Learning SPDFA ---------')
# Learn S-PDFA
flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")

## Copying files
outfile = (outaddress + datafile)
o = (outaddress + modelname)
os.system("dot -Tpng " + outfile + ".ff.final.dot -o " + o + ".png")
# files = [ datafile+'.ff.final.dot', datafile+'.ff.final.dot.json', datafile+'.ff.sinksfinal.json', datafile+'.ff.init_dfa.dot', datafile+'.ff.init_dfa.dot.json']
# outfiles = [ modelname+'.ff.final.dot', modelname+'.ff.final.dot.json', modelname+'.ff.sinksfinal.json', modelname+'.ff.init_dfa.dot', modelname+'.ff.init_dfa.dot.json']
# for (file,out) in zip(files,outfiles):
#    copyfile(outaddress+file, outaddress+out)

path_to_model = outaddress + modelname

print('------ !! Special: Fixing syntax error in sinks files  ---------')
with open(path_to_model + ".ff.sinksfinal.json", 'r') as file:
    filedata = file.read()
filedata = ''.join(filedata.rsplit(',', 1))
with open(path_to_model + ".ff.sinksfinal.json", 'w') as file:
    file.write(filedata)

# '''with open(path_to_model+".ff.final.dot.json", 'r') as file:
#     filedata = file.read()
# filedata = ''.join(filedata.rsplit(',', 1))
# with open(path_to_model+".ff.final.dot.json", 'w') as file:
#     file.write(filedata)'''

print('------ Loading and traversing SPDFA ---------')
# Load S-PDFA
m, data = loadmodel(path_to_model + ".ff.final.dot.json")
m2, data2 = loadmodel(path_to_model + ".ff.sinksfinal.json")

print('------- Encoding into state sequences --------')
# Encoding traces into state sequences
(traces, state_traces) = encode_sequences(m, m2, path_to_traces)
(med_states, sev_states) = find_severe_states(traces, m, m2)
condensed_data = make_condensed_data(alerts, keys, state_traces, med_states, sev_states)

print('------- clustering state groups --------')
state_groups = make_state_groups(condensed_data, modelname)
(condensed_a_data, condensed_v_data) = make_av_data(condensed_data)

print('------- Making alert-driven AGs--------')
make_AG(condensed_v_data, condensed_data, state_groups, modelname, expname)

print('------- FIN -------')
## ----- main END ------
