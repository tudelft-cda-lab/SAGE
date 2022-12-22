# SAGE (IntruSion alert-driven Attack Graph Extractor)
Repository to accompany our publications 

"SAGE: Intrusion Alert-driven Attack Graph Extractor" at VizSec'21, and

"Alert-driven Attack Graph Generation using S-PDFA" at TDSC'21.

## Requires 
- Flexfringe (https://github.com/tudelft-cda-lab/FlexFringe)
- Python packages
  - Graphviz
  - Seaborn
  - Requests
  - [Optional] Fastai (1.0.58)
  - [Optional] Spacy 2.3.5

**Or you can switch to the `docker` branch for a docker container.**


## Usage
`python sage.py {path/to/json/files} {experiment-name} {alert-filtering-window} {alert-aggr-window} {(start_hour,end_hour)}`

- `{path/to/json/files}`: folder containing intrusion alerts in json format. `sample-input.json` provides an example of accepted file format. 
> Ideal setting: One json file for each attacker/team. Filename considered as attacker/team label. 
- `{experiment_name}`: custom name for all artefacts
> Figures, trace files, model files, attack graphs are saved with this prefix for easy identification. 
- `{alert_filtering_window}`: time window in which duplicate alerts are discarded (default: 1.0 sec)
- `{alert_aggr_window}`: aggregate alerts occuring in this window as one episode (default: 150 sec)
- [Optional] `{(start_hour,end_hour)}`: Time range (in hours). A floating-point tuple limiting the alerts that are parsed and involved in the final attack graphs. 
> If not provided, the default values of (0,100) are used, meaning alerts from 0-th to 100-th hour (relative to the start of the alert capture) are parsed.

## First time use

- Set paths to `flexfringe/` `ini-file/` `trace file/` location to store experimental artefacts in `sage.py` script.

**If you use SAGE in a scientific work, consider citing the following papers:**

```
@inproceedings{nadeem2021sage,
  title={SAGE: Intrusion Alert-driven Attack Graph Extractor},
  author={Nadeem, Azqa and Verwer, Sicco and Yang, Shanchieh Jay},
  booktitle={Symposium on Visualization for Cyber Security (Vizec)},
  publisher={IEEE},
  year={2021}
}
```
```
@article{nadeem2021alert,
  title={Alert-driven Attack Graph Generation using S-PDFA},
  author={Nadeem, Azqa and Verwer, Sicco and Moskal, Stephen and Yang, Shanchieh Jay},
  journal={IEEE Transactions on Dependable and Secure Computing (TDSC)},
  year={2021},
  publisher={IEEE}
}
```
```
@inproceedings{nadeem2021enabling,
  title={Enabling visual analytics via alert-driven attack graphs},
  author={Nadeem, Azqa and Verwer, Sicco and Moskal, Stephen and Yang, Shanchieh Jay},
  booktitle={SIGSAC Conference on Computer and Communications Security (CCS)},
  year={2021},
  publisher={ACM}
}
```



#### Azqa Nadeem
#### TU Delft
