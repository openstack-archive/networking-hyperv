#!/bin/bash
DIR_HYPERV=$DEST/networking-hyperv

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    cd $DIR_HYPERV
    echo "Installing Networking-HyperV"
    setup_develop $DIR_HYPERV

    echo "Successfully installed netwroking-hyperv"

fi
