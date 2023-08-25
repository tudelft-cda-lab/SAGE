#!/bin/bash
fil=input.ini
content=`cat $fil`
IFS=$'\n'; params=($content); unset IFS;

EXPNAME=${params[0]#*=}
FILTER=${params[1]#*=}
AGGR=${params[2]#*=}
START_HOUR=${params[3]#*=}
END_HOUR=${params[4]#*=}
DATASET=${params[5]#*=}

python3 sage.py input/ $EXPNAME -t $FILTER -w $AGGR --timerange $START_HOUR $END_HOUR --dataset $DATASET


outnames=$(ls . | grep $EXPNAME)
if [ ! -d /home/out/ ]; then
  mkdir /home/out/
fi
cp -rf $outnames /home/out/
chmod -R a+rwx /home/out/