#!/bin/bash

for t in test*.py 
do 
    echo $t
    python $t
done
