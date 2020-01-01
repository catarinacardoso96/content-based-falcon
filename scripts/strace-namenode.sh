#!/bin/bash

rm -f namenode.out
CMD="/home/hduser/dfs/hadoop/sbin/hadoop-daemon2.sh --config /home/hduser/dfs/hadoop/etc/hadoop --script /home/hduser/dfs/hadoop/sbin/hdfs start namenode"
sudo strace -xx -e trace=read,write,sendfile -o namenode.out -s 65535 -tt -yy -f $CMD
