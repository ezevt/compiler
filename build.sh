#!/bin/sh

echo "Compiling..."

start_time=`date +%s`
g++ src/nex.cpp -o nex
end_time=`date +%s`

echo Done in `expr $end_time - $start_time`s.