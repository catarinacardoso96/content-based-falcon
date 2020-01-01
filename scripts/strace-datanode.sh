#!/bin/bash

rm -f datanode39.out
CMD="/home/hduser/dfs/hadoop/sbin/hadoop-daemon2.sh --config /home/hduser/dfs/hadoop/etc/hadoop --script /home/hduser/dfs/hadoop/sbin/hdfs start datanode"
sudo strace -xx -o datanode39.out -e trace=read,write,sendfile -s 65535 -tt -yy -f $CMD

