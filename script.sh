#!/bin/bash
fil=input.ini
content=`cat $fil`
IFS=$'\n'; params=($content); unset IFS;

EXPNAME=${params[0]#*=}
FILTER=${params[1]#*=}
AGGR=${params[2]#*=}
MODE=${params[3]#*=}

if [ -z "$MODE" ]
then
      python3 ag-gen.py input/ $EXPNAME $FILTER $AGGR
else
      python3 ag-gen.py input/ $EXPNAME $FILTER $AGGR $MODE
fi

outnames=$(ls . | grep $EXPNAME)
if [ ! -d /home/out/ ]; then
  mkdir /home/out/
fi
cp -rf $outnames /home/out/
chmod -R a+rwx /home/out/