# AD-Attack-Graph
Alert-driven attack graph generation pipeline

## Requires 
- Flexfringe
- Graphviz

## Usage
`python ag-gen.py {path/to/json/files} {experiment-name} {alert-filtering-window} {alert-aggr-window} {mode}`

- `{path/to/json/files}`: folder containing intrusion alerts in json format
- `{experiment-name}`: custom name for all artefacts
- `{alert-filtering-window}`: time window in which duplicate alerts are discarded (default: 1.0 sec)
- `{alert-aggr-window}`: aggregate alerts occuring in this window as one episode (default: 150 sec)
- `{mode}`: Special file parsing modes. Leave empty if alerts are in ascending order. Use `2017` or `c2018` otherwise.
