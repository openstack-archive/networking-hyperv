#!/bin/bash

NETWORKING_HYPERV_DIR=$DEST/networking-hyperv

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    cd $NETWORKING_HYPERV_DIR
    echo "Installing networking-hyperv."
    setup_develop $NETWORKING_HYPERV_DIR

    echo "Successfully installed networking-hyperv."
fi
