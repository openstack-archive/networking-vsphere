#!/bin/bash
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

logfile=/var/log/neutron/ovsvapp-agent/monitor.log
broken_msg="ovs: broken"
ok_msg="ovs: ok"
stopped_msg="openvswitch-switch process is not responding. Going to restart"
restarted_msg="openvswitch-switch process is restarted."
if [ ! -f $logfile ]; then
   touch $logfile
   chown neutron:neutron $logfile
   echo $ok_msg >> $logfile
fi

# Case when openvswitch-switch process is not responding.
# Check for ovs-vswitch process.
    sudo ovs-ofctl show br-int
    if [ $? -ne 0 ]; then
       echo $stopped_msg >> $logfile ||true
       sudo service openvswitch-switch stop || true
       sudo service openvswitch-switch start || true
       echo $restarted_msg >> $logfile ||true
       echo $broken_msg >> $logfile
    fi
sleep 1
# Check for ovsdb-server process.
    sudo ovs-vsctl show
    if [ $? -ne 0 ]; then
       echo $stopped_msg >> $logfile || true
       sudo service openvswitch-switch stop || true
       sudo service openvswitch-switch start || true
       echo $restarted_msg >> $logfile || true
       echo $broken_msg >> $logfile
    fi
sleep 2
