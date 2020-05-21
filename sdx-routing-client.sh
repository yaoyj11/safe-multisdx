#!/bin/sh
sbt "project safe-programming" "run -f ${HOME}/safe-multisdx/sdx-routing-client.slang   -jvmm src/main/resources/principal_jvm.map -c 1" 
