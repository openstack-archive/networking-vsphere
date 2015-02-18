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
# - install_networking_vphere
# - install_ovsvapp_agent_packages
# - add_ovsvapp_config
# - configure_ovsvapp_config
# - setup_ovsvapp_bridge
# - start_ovsvapp_agent
# - cleanup_ovsvapp_bridge

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

source $TOP_DIR/lib/neutron_plugins/ovs_base

# Set in local.conf for OVSvApp Solution
# --------

# Provide IP address for vCenter.
OVSVAPP_VCENTER_IP=${OVSVAPP_VCENTER_IP:-None}

# Provide vCenter Credentials.
OVSVAPP_VCENTER_USERNAME=${OVSVAPP_VCENTER_USERNAME:-None}
OVSVAPP_VCENTER_PASSWORD=${OVSVAPP_VCENTER_PASSWORD:-None}

# vCenter server wsdl location.
OVSVAPP_WSDL_LOCATION=${OVSVAPP_WSDL_LOCATION:-https://${OVSVAPP_VCENTER_IP}:443/sdk/vimService.wsdl}

# Provide ESX host name or IP address where OVSvApp VM is hosted.
OVSVAPP_ESX_HOSTNAME=${OVSVAPP_ESX_HOSTNAME:-None}

# Provide Cluster to DVS/vDS mapping.
OVSVAPP_CLUSTER_DVS_MAPPING=${OVSVAPP_CLUSTER_DVS_MAPPING:-DatacenterName/host/ClusterName:vDSName}

# Provide Physical Bridge name.
OVSVAPP_PHYSICAL_BRIDGE=${OVSVAPP_PHYSICAL_BRIDGE:-br-ethx}

# Provide Physical Interface to add port to Physical Bridge.
OVSVAPP_PHYSICAL_INTERFACE=${OVSVAPP_PHYSICAL_INTERFACE:-ethx}

# Provide Trunk Interface.
OVSVAPP_TRUNK_INTERFACE=${OVSVAPP_TRUNK_INTERFACE:-ethy}

# Provide Physical Bridge Mappings.
OVSVAPP_BRIDGE_MAPPINGS=${OVSVAPP_BRIDGE_MAPPINGS:-physnet1:ethx}

# Provide Security Bridge Mapping.
OVSVAPP_SECURITY_BRIDGE_MAPPINGS=${OVSVAPP_SECURITY_BRIDGE_MAPPINGS:-br-sec:ethy}

# Provide Integration Bridge.
INTEGRATION_BRIDGE=${INTEGRATION_BRIDGE:-br-int}

# Provide Security Bridge.
SECURITY_BRIDGE=${SECURITY_BRIDGE:-br-sec}

# OVSvApp Networking-vSphere DIR.
OVSVAPP_NETWORKING_DIR=$DEST/networking-vsphere

# Entry Points
# ------------

# Test if OVSvApp is enabled
# is_ovsvapp_enabled
function is_ovsvapp_enabled {
    [[ ,${ENABLED_SERVICES} =~ ,"ovsvapp-" ]] && return 0
    return 1
}

function start_ovsvapp_agent {
    OVSVAPP_AGENT_BINARY="$NEUTRON_BIN_DIR/neutron-ovsvapp-agent"
    echo "Starting OVSvApp L2 Agent"
    run_process ovsvapp-agent "python $OVSVAPP_AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$OVSVAPP_CONF_FILE"
}

function cleanup_ovsvapp_bridges {
    echo "Removing Bridges for OVSvApp L2 Agent"
    sudo ovs-vsctl del-br $INTEGRATION_BRIDGE
    sudo ovs-vsctl del-br $SECURITY_BRIDGE
    sudo ovs-vsctl del-br $OVSVAPP_PHYSICAL_BRIDGE
}

function setup_ovsvapp_bridges {
    echo "Adding Bridges for OVSvApp L2 Agent"
    sudo ovs-vsctl --no-wait -- --may-exist add-br $INTEGRATION_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-br $SECURITY_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-br $OVSVAPP_PHYSICAL_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-port $OVSVAPP_PHYSICAL_BRIDGE $OVSVAPP_PHYSICAL_INTERFACE
    sudo ovs-vsctl --no-wait -- --may-exist add-port $SECURITY_BRIDGE $OVSVAPP_TRUNK_INTERFACE
}

function _populate_ovsvapp_config {
    CONF=$1
    SECTION=$2
    OPTS=$3

    if [ -z "$OPTS" ]; then
        return
    fi
    for I in "${OPTS[@]}"; do
        # Replace the first '=' with ' ' for iniset syntax
        iniset $CONF $SECTION ${I/=/ }
    done
}

function configure_ovsvapp_config {
    echo "Configuring ovsvapp_agent.ini for OVSvApp"
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware vcenter_ip=$OVSVAPP_VCENTER_IP
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware vcenter_username=$OVSVAPP_VCENTER_USERNAME
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware vcenter_password=$OVSVAPP_VCENTER_PASSWORD
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware wsdl_location=$OVSVAPP_WSDL_LOCATION
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware cluster_dvs_mapping=$OVSVAPP_CLUSTER_DVS_MAPPING
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE vmware esx_hostname=$OVSVAPP_ESX_HOSTNAME
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE ovsvapp bridge_mappings=$OVSVAPP_BRIDGE_MAPPINGS
    _populate_ovsvapp_config /$OVSVAPP_CONF_FILE securitygroup security_bridge_mapping=$OVSVAPP_SECURITY_BRIDGE_MAPPINGS
}

function add_ovsvapp_config {
    OVSVAPP_CONF_PATH=etc/neutron/plugins/ovsvapp
    OVSVAPP_CONF_FILENAME=ovsvapp_agent.ini
    mkdir -p /$OVSVAPP_CONF_PATH
    OVSVAPP_CONF_FILE=$OVSVAPP_CONF_PATH/$OVSVAPP_CONF_FILENAME
    echo "Adding configuration file for OVSvApp Agent"
    cp $OVSVAPP_NETWORKING_DIR/$OVSVAPP_CONF_FILE /$OVSVAPP_CONF_FILE
}

function install_ovsvapp_agent_packages {
    echo "Installing Openvswitch"
    _neutron_ovs_base_install_agent_packages
}

function install_networking_vsphere {
    cd $OVSVAPP_NETWORKING_DIR
    echo "Installing the Networking-vSphere for OVSvApp"
    sudo python setup.py install
}

# main loop
if is_service_enabled ovsvapp-server; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_networking_vsphere
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

if is_service_enabled ovsvapp-agent; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_networking_vsphere
        install_ovsvapp_agent_packages
        add_ovsvapp_config
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovsvapp_config
        setup_ovsvapp_bridges
        start_ovsvapp_agent
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
       cleanup_ovsvapp_bridges
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_ovsvapp_bridges
    fi
fi
# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:
