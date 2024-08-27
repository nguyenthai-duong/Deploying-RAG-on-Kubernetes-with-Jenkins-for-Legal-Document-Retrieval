#!/bin/bash
sudo docker restart a33fa7798acd
sleep 20
while true; do
  ssh -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -R nthaiduong83:80:127.0.0.1:8080 serveo.net
  sleep 30
done