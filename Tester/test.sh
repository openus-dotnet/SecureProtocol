#!/bin/bash

for a in 0 5 10 15 20 25
do
    for b in 1 10 100
    do
        for re in 0 0 0 0 0
        do
            ./Tester s $a $b
        done
    done
done
