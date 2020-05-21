#!/bin/bash
cd ~/safe
sbt  "project safe-server" "run -f ${HOME}/safe-multisdx/sdx-routing.slang  -r safeService  -kd   src/main/resources/prdnsmall" 
