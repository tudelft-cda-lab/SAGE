#!/bin/bash
docker build -t $1 .
winpty docker run -it --mount src=$PWD/output,target=/home/out,type=bind --mount src=$PWD/alerts,target=/root/input,type=bind $1:latest 

while :; do echo 'Hit CTRL+C'; sleep 1; done
