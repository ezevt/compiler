#!/bin/sh

echo "Compiling..."

start_time=`date +%s`
g++ src/main.cpp -o compiler
end_time=`date +%s`

echo Done in `expr $end_time - $start_time`s.