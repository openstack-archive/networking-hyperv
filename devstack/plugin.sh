#!/bin/bash

# Configure the needed tempest options
function configure_networking-hyperv_tempest() {
    initset $TEMPEST_CONFIG service_available networking-hyperv True
    # NOTE: Check what config options tempest needs regarding networking-hyperv
}

DIR_HYPERV=$DEST/networking-hyperv

if is_service_enabled networking-hyperv; then

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        #if is_service_enabled
        cd $DIR_HYPERV
        echo "Installing Networking-HyperV"
        setup_develop $DIR_HYPERV
    fi

    if [[ "$1" == "unstack" ]]; then
      :
      # NOTE: Check what should be done here too
      #       Is there anything that should be done here?
    fi

    if [[ "$1" == "clean" ]]; then
      :
      # NOTE: Check what should be done here too
      #       Is there anything that should be done here?
    fi
fi
