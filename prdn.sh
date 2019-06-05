#!/bin/bash
cd ~/safe
sbt  "project safe-server" "run -f /root/safe-apps/stitch-all.slang  -r safeService  -kd   src/main/resources/prdnsmall" 
