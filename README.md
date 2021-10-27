# SAGE (IntruSion alert-driven Attack Graph Extractor)
Repository to accompany our publications 

"SAGE: Intrusion Alert-driven Attack Graph Extractor" at VizSec'21, and

"Alert-driven Attack Graph Generation using S-PDFA" at TDSC'21.

## Requires 
- Flexfringe (https://bitbucket.org/chrshmmmr/dfasat/src/master/)
- Graphviz

**Or you can switch to the `docker` branch for a docker container.**


## Usage
`python sage.py {path/to/json/files} {experiment-name} {alert-filtering-window} {alert-aggr-window} {mode}`

- `{path/to/json/files}`: folder containing intrusion alerts in json format. 
> Ideal setting: One json file for each attacker/team. Filename considered as attacker/team label. 
- `{experiment-name}`: custom name for all artefacts
> Figures, trace files, model files, attack graphs are saved with this prefix for easy identification. 
- `{alert-filtering-window}`: time window in which duplicate alerts are discarded (default: 1.0 sec)
- `{alert-aggr-window}`: aggregate alerts occuring in this window as one episode (default: 150 sec)
- `{mode}`: Special file parsing modes. _Leave empty_ if alerts are in ascending order. Use `2017` or `c2018` otherwise.

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
