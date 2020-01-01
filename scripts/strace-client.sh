#!/bin/bash

rm -f client.out
CMD="/home/hduser/dfs/hadoop/bin/hdfs dfs"
sudo strace -xx -o client.out -e trace=read,write,sendfile -s 65535 -tt -yy -f $CMD $@

