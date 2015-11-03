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
# - install_ovsvapp_dependency
# - install_nginx_server
# - install_networking_vsphere
# - run_ovsvapp_alembic_migration
# - pre_configure_ovsvapp
# - add_ovsvapp_config
# - configure_ovsvapp_config
# - setup_ovsvapp_bridges
# - start_ovsvapp_agent
# - create_monitor_log_files
# - start_ovsvapp_agent_monitor
# - configure_ovsvapp_compute_driver
# - cleanup_ovsvapp_bridges
# - configure_nginx_default

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

source $TOP_DIR/lib/neutron_plugins/ovs_base

# OVSvApp Networking-vSphere DIR.
OVSVAPP_NETWORKING_DIR=$DEST/networking-vsphere

# Nova VMwareVCDriver DIR
NOVA_VCDRIVER=$NOVA_DIR/nova/virt/vmwareapi/

# OVSvApp VCDriver file path
OVSVAPP_VCDRIVER=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/ovsvapp_vc_driver.py

# OVSvApp VMops file path
OVSVAPP_VMOPS=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/ovsvapp_vmops.py


# Entry Points
# ------------

function configure_ovsvapp_monitoring {
   echo "Configuring ml2_conf.ini for OVSvApp Monitoring"
   iniset /$Q_PLUGIN_CONF_FILE ovsvapp enable_ovsvapp_monitor $ENABLE_OVSVAPP_MONITOR
}

function configure_ovsvapp_compute_driver {
    echo "Configuring Nova VCDriver for OVSvApp"
    cp $OVSVAPP_VCDRIVER $NOVA_VCDRIVER
    cp $OVSVAPP_VMOPS $NOVA_VCDRIVER
    iniset $NOVA_CONF DEFAULT compute_driver "vmwareapi.ovsvapp_vc_driver.OVSvAppVCDriver"
}

function start_ovsvapp_agent {
    OVSVAPP_AGENT_BINARY="$NEUTRON_BIN_DIR/neutron-ovsvapp-agent"
    echo "Starting OVSvApp Agent"
    run_process ovsvapp-agent "python $OVSVAPP_AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$OVSVAPP_CONF_FILE"
}

function start_ovsvapp_agent_monitor {
    OVSVAPP_AGENT_MONITOR_BINARY="$NEUTRON_BIN_DIR/neutron-ovsvapp-agent-monitor"
    echo "Starting OVSvApp Agent Monitor"
    run_process ovsvapp-agent-monitor "python $OVSVAPP_AGENT_MONITOR_BINARY --config-file /$OVSVAPP_CONF_FILE"
}

function cleanup_ovsvapp_bridges {
    echo "Removing Bridges for OVSvApp Agent"
    sudo ovs-vsctl del-br $INTEGRATION_BRIDGE
    sudo ovs-vsctl del-br $TUNNEL_BRIDGE
    sudo ovs-vsctl del-br $SECURITY_BRIDGE
    sudo ovs-vsctl del-br $OVSVAPP_PHYSICAL_BRIDGE
}

function setup_ovsvapp_bridges {
    echo "Adding Bridges for OVSvApp Agent"
    sudo ovs-vsctl --no-wait -- --may-exist add-br $INTEGRATION_BRIDGE
    if [ "$OVSVAPP_TENANT_NETWORK_TYPE" == "vxlan" ]; then
        sudo ovs-vsctl --no-wait -- --may-exist add-br $TUNNEL_BRIDGE
    else
        sudo ovs-vsctl --no-wait -- --may-exist add-br $OVSVAPP_PHYSICAL_BRIDGE
        sudo ovs-vsctl --no-wait -- --may-exist add-port $OVSVAPP_PHYSICAL_BRIDGE $OVSVAPP_PHYSICAL_INTERFACE
    fi
    sudo ovs-vsctl --no-wait -- --may-exist add-br $SECURITY_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-port $SECURITY_BRIDGE $OVSVAPP_TRUNK_INTERFACE
}

function configure_ovsvapp_config {
    echo "Configuring ovsvapp_agent.ini for OVSvApp"
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_ip $OVSVAPP_VCENTER_IP
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_username $OVSVAPP_VCENTER_USERNAME
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_password $OVSVAPP_VCENTER_PASSWORD
    iniset /$OVSVAPP_CONF_FILE vmware wsdl_location $OVSVAPP_WSDL_LOCATION
    iniset /$OVSVAPP_CONF_FILE vmware cluster_dvs_mapping $OVSVAPP_CLUSTER_DVS_MAPPING
    iniset /$OVSVAPP_CONF_FILE vmware esx_hostname $OVSVAPP_ESX_HOSTNAME
    if [ "$OVSVAPP_TENANT_NETWORK_TYPE" == "vxlan" ]; then
        iniset /$OVSVAPP_CONF_FILE ovsvapp tenant_network_type $OVSVAPP_TENANT_NETWORK_TYPE
        iniset /$OVSVAPP_CONF_FILE ovsvapp local_ip $OVSVAPP_LOCAL_IP
    else
        iniset /$OVSVAPP_CONF_FILE ovsvapp bridge_mappings $OVSVAPP_BRIDGE_MAPPINGS
    fi
    iniset /$OVSVAPP_CONF_FILE securitygroup security_bridge_mapping $OVSVAPP_SECURITY_BRIDGE_MAPPINGS
}

function add_ovsvapp_config {
    OVSVAPP_CONF_PATH=etc/neutron/plugins/ml2
    OVSVAPP_CONF_FILENAME=ovsvapp_agent.ini
    mkdir -p /$OVSVAPP_CONF_PATH
    OVSVAPP_CONF_FILE=$OVSVAPP_CONF_PATH/$OVSVAPP_CONF_FILENAME
    echo "Adding configuration file for OVSvApp Agent"
    cp $OVSVAPP_NETWORKING_DIR/$OVSVAPP_CONF_FILE /$OVSVAPP_CONF_FILE
}

function pre_configure_ovsvapp {
    echo "Configuring Neutron for OVSvApp Agent"
    configure_neutron
    _configure_neutron_service
}

function run_ovsvapp_alembic_migration {
    $NEUTRON_BIN_DIR/neutron-ovsvapp-db-manage --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE upgrade head
}

function install_ovsvapp_dependency {
    echo "Installing dependencies for OVSvApp"
    install_nova
    install_neutron
    _neutron_ovs_base_install_agent_packages
    install_nginx_server
}

function install_nginx_server {
    echo "Installing nginx_server"
    sudo apt-get install nginx
}

function configure_nginx_default {
    NGINX_DEFAULT_PATH=etc/nginx/sites-available
    NGINX_DEFAULT_FILENAME=default
    mkdir -p /$NGINX_DEFAULT_PATH
    NGINX_DEFAULT_FILE=$NGINX_DEFAULT_PATH/$NGINX_DEFAULT_FILENAME
    echo "Adding configuration file for nginx server"
    sudo cp $OVSVAPP_NETWORKING_DIR/etc/nginx-default /$NGINX_DEFAULT_FILE
    sudo sed -i "s%<monitoring_ip>%$OVSVAPP_MONITORING_IP%g" "/$NGINX_DEFAULT_FILE"

    NGINX_DEFAULT_JSON_PATH=$(dirname "${OVSVAPP_STATUS_JSON_PATH}")
    sudo sed -i "s%/var/log/neutron/ovsvapp-agent%$NGINX_DEFAULT_JSON_PATH%g" "/$NGINX_DEFAULT_FILE"

    iniset /$OVSVAPP_CONF_FILE ovsvapp_monitoring monitoring_ip $OVSVAPP_MONITORING_IP
    iniset /$OVSVAPP_CONF_FILE ovsvapp_monitoring monitor_log_path $OVSVAPP_MONITORING_LOG_PATH
    iniset /$OVSVAPP_CONF_FILE ovsvapp_monitoring status_json_path $OVSVAPP_STATUS_JSON_PATH

    sudo service nginx restart

function install_networking_vsphere {
    echo "Installing the Networking-vSphere for OVSvApp"
    setup_develop $OVSVAPP_NETWORKING_DIR
}

function create_monitor_log_files {
    if [ ! -f $logfile ]; then
        touch $OVSVAPP_MONITORING_LOG_PATH
        touch $OVSVAPP_STATUS_JSON_PATH
    fi
    OVSVAPP_MONITOR_PATH=opt/stack/networking-vsphere/networking_vsphere/monitor
    OVSVAPP_MONITOR_FILENAME=ovsvapp-agent-monitor.sh
    mkdir -p /$OVSVAPP_MONITOR_PATH
    OVSVAPP_MONITOR_FILE=$OVSVAPP_MONITOR_PATH/$OVSVAPP_MONITOR_FILENAME
    sudo sed -i "s%/var/log/neutron/ovsvapp-agent/monitor.log%$OVSVAPP_MONITORING_LOG_PATH%g" "/$OVSVAPP_MONITOR_FILE"
}

# main loop
if is_service_enabled ovsvapp-server; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_ovsvapp_dependency
        install_networking_vsphere
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovsvapp_monitoring
        run_ovsvapp_alembic_migration
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
        install_ovsvapp_dependency
        install_networking_vsphere
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        pre_configure_ovsvapp
        add_ovsvapp_config
        configure_ovsvapp_config
        setup_ovsvapp_bridges
        start_ovsvapp_agent
        create_monitor_log_files
        start_ovsvapp_agent_monitor
        configure_nginx_default
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

if is_service_enabled ovsvapp-compute; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_ovsvapp_dependency
        install_networking_vsphere
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovsvapp_compute_driver
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

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:
