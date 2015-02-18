#!/bin/bash
#
# devstack/plugin.sh
# Functions to control the configuration and operation of the OVSvApp solution
# Dependencies:
#
# ``functions`` file
# ``DEST`` must be defined
# ``STACK_USER`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
# - is_ovsvapp_enabled


# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

# Defaults
# --------
# The OVSvApp Networking-vSphere DIR
OVSVAPP_NETWORKING_DIR=$DEST/networking-vsphere

# Entry Points
# ------------

# Test if OVSvApp is enabled
# is_ovsvapp_enabled
function is_ovsvapp_enabled {
    [[ ,${ENABLED_SERVICES} =~ ,"ovsvapp-" ]] && return 0
    return 1
}


function install_ovsvapp_neutron_thin_ml2_driver {
    cd $OVSVAPP_NETWORKING_DIR
    echo "Installing the Networking-vSphere driver for OVSvApp"
    sudo python setup.py install
}

# main loop
if is_service_enabled ovsvapp-server; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_ovsvapp_neutron_thin_ml2_driver
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi
fi

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:
