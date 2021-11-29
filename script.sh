#!/bin/bash
fil=input.ini
content=`cat $fil`
IFS=$'\n'; params=($content); unset IFS;

EXPNAME=${params[0]#*=}
FILTER=${params[1]#*=}
AGGR=${params[2]#*=}

python3 sage.py input/ $EXPNAME $FILTER $AGGR


outnames=$(ls . | grep $EXPNAME)
if [ ! -d /home/out/ ]; then
  mkdir /home/out/
fi
cp -rf $outnames /home/out/
chmod -R a+rwx /home/out/