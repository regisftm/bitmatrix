#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../env.sh

P4C_BM_SCRIPT=/usr/local/bin/p4c

SWITCH_PATH=/usr/local/bin/simple_switch

CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py

sudo $SWITCH_PATH >/dev/null 2>&1
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python topo.py \
    --behavioral-exe $SWITCH_PATH \
    --json p4prog/bitmatrix.json \
    --cli $CLI_PATH
