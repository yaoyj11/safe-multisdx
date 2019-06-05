#!/bin/bash
cd ~/safe
/root/sbt/bin/sbt  "project safe-server" "run -f /root/safe-apps/sdx-routing.slang  -r safeService  -kd   src/main/resources/prdnsmall" 
