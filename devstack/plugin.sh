#!/bin/bash
DIR_HYPERV=$DEST/networking-hyperv

if is_service_enabled networking-hyperv; then

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        #if is_service_enabled
        cd $DIR_HYPERV
        echo "Installing Networking-HyperV"
        setup_develop $DIR_HYPERV

        echo "Successfully installed netwroking-hyperv"

    fi
fi
