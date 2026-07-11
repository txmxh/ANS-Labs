#!/bin/bash

N=${1:-2}
SCRIPT=${2:-worker.py}

for ((i=1; i<=N; i++)); do
    setsid mx h$i python "$SCRIPT" $((i-1)) $N > "log/worker$i.log" 2>&1 < /dev/null &
done

wait
echo "done"
