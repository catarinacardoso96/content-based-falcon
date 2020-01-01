#!/bin/bash

mkdir $1
cd $1

scp hduser@cloud38.cluster.lsd.di.uminho.pt:client.out client-all.out &
scp hduser@cloud38.cluster.lsd.di.uminho.pt:namenode.out namenode-all.out &
scp hduser@cloud39.cluster.lsd.di.uminho.pt:datanode39.out datanode39-all.out &
scp hduser@cloud40.cluster.lsd.di.uminho.pt:datanode40.out datanode40-all.out &

wait

cat client-all.out | grep "TCP:" > client-tcp.out
cat namenode-all.out | grep "TCP:" > namenode-tcp.out
cat datanode39-all.out | grep "TCP:" > datanode39-tcp.out
cat datanode40-all.out | grep "TCP:" > datanode40-tcp.out
