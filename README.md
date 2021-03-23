#### Docker for Attack graph generation

# important files
- Dockerfile
- script.sh
- input.ini
- requirements.txt
- batch-likelihoodRIT.txt
- ag-gen.py (hopefully will be pulling from github soon)

# Create folders
- /alerts/ containing alerts in .json files
- /output/ will be mounted to docker and will contain all outputs

# Pre-reqs
- Install and setup docker

# Directions
- First, create a new folder X and pull all relavent files and create relavent folders
- Then open `input.ini` and update `experiment-name` field. To play around, you can also modify `alert-filtering-window` and `alert-aggr-window`. To see how to set these values, look up the main AD-Attack-Graph github.
- Next, open a cmd/shell in folder X and build the docker image:

`docker build -t {Image Name} . `, e.g. `docker build -t ag-test .`

- Next, create a docker container based on the image while also mouting the local drive to store all outputs:

`docker run -it --mount src=%cd%/output,target=/home/out,type=bind {Image Name}`, e.g. `docker run -it --mount src=%cd%/output,target=/home/out,type=bind ag-test`

* For Linux, replace %cd% with `pwd`.

- Wait for execution. Once finished, the output artefacts can be found in X/output/  