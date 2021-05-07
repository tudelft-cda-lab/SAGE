# SAGE (IntruSion alert-driven Attack Graph Extractor)
Alert-driven attack graph generation pipeline

## Requires 
- Flexfringe 
- Graphviz

## Usage
`python ag-gen.py {path/to/json/files} {experiment-name} {alert-filtering-window} {alert-aggr-window} {mode}`

- `{path/to/json/files}`: folder containing intrusion alerts in json format. 
> Ideal setting: One json file for each attacker/team. Filename considered as attacker/team label. 
- `{experiment-name}`: custom name for all artefacts
> Figures, trace files, model files, attack graphs are saved with this prefix for easy identification. 
- `{alert-filtering-window}`: time window in which duplicate alerts are discarded (default: 1.0 sec)
- `{alert-aggr-window}`: aggregate alerts occuring in this window as one episode (default: 150 sec)
- `{mode}`: Special file parsing modes. _Leave empty_ if alerts are in ascending order. Use `2017` or `c2018` otherwise.

## First time use

- Set paths to flexfringe/ ini-file/ trace file/ location to store experimental artefacts in `ag_gen.py` script.
