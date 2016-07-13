# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import eventlet
import greenlet
import os
from oslo_config import cfg
from oslo_log import log

from networking_vsphere._i18n import _LE, _LW
from networking_vsphere.drivers import base_manager
from networking_vsphere.drivers import dvs_driver
from networking_vsphere.utils import vim_session

LOG = log.getLogger(__name__)


class VcenterManager(base_manager.DriverManager):

    def __init__(self, netcallback):
        base_manager.DriverManager.__init__(self)
        self.netcallback = netcallback
        self.vcenter_ip = None
        self.vcenter_username = None
        self.vcenter_password = None
        self.vcenter_api_retry_count = None
        self.wsdl_location = None
        self.cluster_switch_mapping = {}
        self.connection_thread = None
        self.https_port = cfg.CONF.VMWARE.https_port

    def _parse_mapping(self, entry):
        """Parse an entry of cluster_dvs_mapping.

        :param entry: String value which is an entry in conf file
                      for cluster_dvs_mapping.
                      Could be a simple mapping in the form
                      clusterpath:dvsname or a comma separated one like
                      clusterpath1:dvsname1,clusterpath2:dvsname2
        :returns: A list of (cluster, dvs) tuples
        """
        try:
            cluster_dvs_list = []
            LOG.debug("Parsing cluster_dvs_mapping %s.", entry)
            mappings = entry.split(",")
            for mapping in mappings:
                cluster = None
                vds = None
                if ":" in mapping:
                    cluster, vds = mapping.split(":", 1)
                    cluster = cluster.strip()
                    vds = vds.strip()
                if not cluster or not vds:
                    LOG.error(_LE("Invalid value %s for opt "
                                  "cluster_dvs_mapping."), mapping)
                else:
                    cluster_dvs_list.append((cluster, vds))
        except Exception:
            LOG.exception(_LE("Invalid value %s for opt cluster_dvs_mapping."),
                          entry)
        return cluster_dvs_list

    def _add_cluster(self, cluster, vds):
        try:
            self.driver.add_cluster(cluster, vds)
        except Exception:
            LOG.exception(_LE("Adding cluster %(cluster)s:%(vds)s failed."),
                          {'cluster': cluster, 'vds': vds})
        else:
            self.cluster_switch_mapping[cluster] = vds

    def initialize_driver(self):
        self.stop()
        self.driver = None
        self.vcenter_ip = cfg.CONF.VMWARE.vcenter_ip
        self.vcenter_username = cfg.CONF.VMWARE.vcenter_username
        self.vcenter_password = cfg.CONF.VMWARE.vcenter_password
        self.vcenter_api_retry_count = cfg.CONF.VMWARE.vcenter_api_retry_count
        self.wsdl_location = cfg.CONF.VMWARE.wsdl_location
        self.https_port = cfg.CONF.VMWARE.https_port
        self.ca_path = None
        if cfg.CONF.VMWARE.cert_check:
            if not cfg.CONF.VMWARE.cert_path:
                LOG.error(_LE("SSL certificate path is not defined to "
                              "establish secure vCenter connection. "
                              "Aborting agent!"))
                raise SystemExit(1)
            elif not os.path.isfile(cfg.CONF.VMWARE.cert_path):
                LOG.error(_LE("SSL certificate does not exist at "
                              "the specified path %s. Aborting agent!"),
                          cfg.CONF.VMWARE.cert_path)
                raise SystemExit(1)
            else:
                self.ca_path = cfg.CONF.VMWARE.cert_path
        if (self.vcenter_ip and self.vcenter_username and
                self.vcenter_password and self.wsdl_location):
            vim_session.ConnectionHandler.set_vc_details(
                self.vcenter_ip,
                self.vcenter_username,
                self.vcenter_password,
                self.vcenter_api_retry_count,
                self.wsdl_location,
                self.ca_path,
                self.https_port)
            vim_session.ConnectionHandler.start()
            if self.connection_thread:
                self.connection_thread.kill()
            self.connection_thread = eventlet.spawn(
                vim_session.ConnectionHandler.try_connection)
            try:
                self.connection_thread.wait()
            except greenlet.GreenletExit:
                LOG.warning(_LW("Thread waiting on vCenter connection "
                                "exited."))
                return
        else:
            LOG.error(_LE("Must specify vcenter_ip, vcenter_username, "
                          "vcenter_password and wsdl_location."))
            return
        self.driver = dvs_driver.DvsNetworkDriver()
        self.driver.set_callback(self.netcallback)
        for mapping in cfg.CONF.VMWARE.cluster_dvs_mapping:
            cluster_dvs_list = self._parse_mapping(mapping)
            for cluster, vds in cluster_dvs_list:
                self._add_cluster(cluster, vds)

    def start(self):
        """Start the driver event monitoring."""
        if self.driver:
            eventlet.spawn_n(self.driver.monitor_events)

    def pause(self):
        """Pause the driver."""
        if self.driver:
            self.driver.pause()

    def stop(self):
        """Stop driver and connection."""
        if self.driver:
            self.driver.stop()
        vim_session.ConnectionHandler.stop()
