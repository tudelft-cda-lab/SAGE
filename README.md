# Docker for SAGE: Attack Graph Generator
Repository to accompany our publications 

"SAGE: Intrusion Alert-driven Attack Graph Extractor" at VizSec'21, and 

"Alert-driven Attack Graph Generation using S-PDFA" at TDSC'21..

## Important files
- Dockerfile
- script.sh
- start.sh
- input.ini
- spdfa-config.ini
- requirements.txt


## Create folders
- /alerts/ containing intrusion alert files in `.json` format
- /output/ will be mounted to docker and will contain all outputs

## Pre-reqs
- Install and setup `docker`

## Usage Instructions

- First, create a new folder X and pull all relavent files and create relavent folders
- Then open `input.ini` and update `experiment-name` field. To play around, you can also modify `alert-filtering-window` and `alert-aggr-window`. To see how to set these values, look up the main branch of [SAGE](https://github.com/tudelft-cda-lab/SAGE).

### Option I: Fastest way

- Open a cmd/shell in folder X and execute the following command:

`start.sh {Image Name}`, \
e.g. `start.sh ag-test .`

- Wait for execution. Once finished, the attack graphs can be found in X/output/

### Option II: Configure Docker Yourself

- Open a cmd/shell in folder X and build the docker image:

`docker build -t {Image Name} . `, \
e.g. `docker build -t ag-test .`

- Next, create a docker container based on the image while also mouting the local drive to store all outputs:

`docker run -it \` \
  `--mount src=%cd%/output,target=/home/out,type=bind \` \
  `--mount src=%cd%/alerts,target=/root/input,type=bind \` \
  `{Image Name}  `, \
e.g. `docker run -it \` \
  `--mount src=%cd%/output,target=/home/out,type=bind \` \
  `--mount src=%cd%/alerts,target=/root/input,type=bind \` \
  `ag-test`

* For Linux, replace `%cd%` with `$(pwd)`.

- Wait for execution. Once finished, the output artefacts can be found in X/output/  

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
