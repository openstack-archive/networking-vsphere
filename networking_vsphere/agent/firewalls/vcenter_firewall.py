# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from multiprocessing import Process, Queue
import signal
import threading
import time
import traceback

from neutron.agent import firewall
from oslo_log import log as logging
from oslo_vmware import exceptions as vmware_exceptions

from networking_vsphere.common import exceptions
from networking_vsphere._i18n import _LI
from networking_vsphere.common import vmware_conf as config
from networking_vsphere.utils import dvs_util
from networking_vsphere.utils import security_group_utils as sg_util


LOG = logging.getLogger(__name__)

CONF = config.CONF
CLEANUP_REMOVE_TASKS_TIMEDELTA = 60


def firewall_main(list_queues, remove_queue):
    dvs_firewall = DVSFirewallUpdater(list_queues, remove_queue)
    signal.signal(signal.SIGTERM, dvs_firewall._handle_sigterm)
    dvs_firewall.updater_loop()


class DVSFirewallUpdater(object):

    def __init__(self, list_queues, remove_queue):
        self.pq = PortQueue(list_queues, remove_queue)
        self.run_daemon_loop = True
        self.pq.port_updater_loop()

    def updater_loop(self):
        while self.run_daemon_loop:
            try:
                dvs, r_ports = self.pq.get_remove_tasks()
                if dvs and r_ports:
                    remover(dvs, r_ports)

                dvs, ports = self.pq.get_update_tasks()
                if dvs and ports:
                    updater(dvs, ports)
                else:
                    time.sleep(1)
            except (vmware_exceptions.VMwareDriverException,
                    exceptions.VMWareDVSException) as e:
                LOG.debug("Exception was handled in firewall updater: %s. "
                          "Traceback: %s" % (e, traceback.format_exc()))

    def _handle_sigterm(self, signum, frame):
        LOG.info(_LI("Termination of firewall process called"))
        self.run_daemon_loop = False


class PortQueue(object):
    def __init__(self, list_queues, remove_queue):
        self.list_queues = list_queues
        self.remove_queue = remove_queue
        self.removed = {}
        self.update_store = {}
        self.remove_store = {}
        self.networking_map = dvs_util.create_network_map_from_config(
            CONF.ML2_VMWARE)

    # Todo: add roundrobin for active DVS. SlOPS
    def get_update_tasks(self, number=5):
        for dvs, tasks in self.update_store.iteritems():
            if tasks:
                ret = tasks[:number]
                self.update_store[dvs] = tasks[number:]
                return dvs, ret
        return None, []

    def get_remove_tasks(self):
        ret = []
        for dvs, tasks in self.remove_store.iteritems():
            for task in tasks:
                key = task.get('binding:vif_details', {}).get('dvs_port_key')
                if dvs.check_free(key):
                    ret.append(task)
                    self.remove_store[dvs].remove(task)
            if ret:
                return dvs, ret
        return None, []

    def _get_update_tasks(self):
        for queue in self.list_queues:
            while not queue.empty():
                request = queue.get()
                for port in request:
                    dvs = self.get_dvs(port)
                    if dvs:
                        stored_tasks = self.update_store.get(dvs, [])
                        index = next((i for i, p in enumerate(stored_tasks)
                                      if p['id'] == port['id']), None)
                        if index is not None:
                            stored_tasks[index] = port
                        else:
                            stored_tasks.append(port)
                        self.update_store[dvs] = stored_tasks

    def _get_remove_tasks(self):
        while not self.remove_queue.empty():
            port = self.remove_queue.get()
            dvs = self.get_dvs(port)
            if dvs:
                self.remove_store.setdefault(dvs, []).append(port)
                self.removed[port['id']] = time.time()

    def _cleanup_removed(self):
        current_time = time.time()
        for port_id, remove_time in self.removed.items():
            if current_time - remove_time > CLEANUP_REMOVE_TASKS_TIMEDELTA:
                del self.removed[port_id]

    def get_dvs(self, port):
        dvs_uuid = port.get('binding:vif_details', {}).get('dvs_id')
        dvs = dvs_util.get_dvs_by_uuid(
            self.networking_map.values(), dvs_uuid)
        return dvs

    def port_updater_loop(self):
        self._get_update_tasks()
        self._get_remove_tasks()
        for dvs in self.update_store:
            self.update_store[dvs] = [item for item in self.update_store[dvs]
                                      if item['id'] not in self.removed]
        self._cleanup_removed()
        threading.Timer(1, self.port_updater_loop).start()


@dvs_util.wrap_retry
def updater(dvs, port_list):
    sg_util.update_port_rules(dvs, port_list)


def remover(dvs, ports_list):
    for port in ports_list:
        if dvs:
            dvs.release_port(port)


class DVSFirewallDriver(firewall.FirewallDriver):
    """DVS Firewall Driver.
    """
    def __init__(self):
        self.dvs_ports = {}
        self._defer_apply = False
        self.list_queues = []
        for x in xrange(10):
            self.list_queues.append(Queue())
        self.remove_queue = Queue()
        self.fw_process = Process(
            target=firewall_main, args=(self.list_queues, self.remove_queue))
        self.fw_process.start()
        self.networking_map = dvs_util.create_network_map_from_config(
            CONF.ML2_VMWARE)

    def _get_port_dvs(self, port):
        dvs_uuid = port.get('binding:vif_details', {}).get('dvs_id')
        dvs = dvs_util.get_dvs_by_uuid(
            self.networking_map.values(), dvs_uuid)
        return dvs

    def stop_all(self):
        self.fw_process.terminate()

    def prepare_port_filter(self, ports):
        self._process_port_filter(ports)

    def apply_port_filter(self, ports):
        self._process_port_filter(ports)

    def update_port_filter(self, ports):
        self._process_port_filter(ports)

    def _process_port_filter(self, ports):
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])
        ports_for_update = []
        for port in ports:
            port_device = port['device']
            stored_port_key = self.dvs_ports.get(port_device, {}).\
                get('binding:vif_details', {}).get('dvs_port_key')
            port_key = port.get('binding:vif_details', {}).get('dvs_port_key')
            if port_key and port_key != stored_port_key:
                port_dvs = self._get_port_dvs(port)
                if port_dvs:
                    try:
                        port_info = port_dvs.get_port_info(port)
                        if port['id'] == port_info.config.name:
                            self.dvs_ports[port_device] = port
                            ports_for_update.append(port)
                        else:
                            self.dvs_ports.pop(port_device, None)
                    except exceptions.PortNotFound:
                        self.dvs_ports.pop(port_device, None)
                else:
                    self.dvs_ports.pop(port_device, None)
            else:
                self.dvs_ports[port_device] = port
                ports_for_update.append(port)
        self._apply_sg_rules_for_port(ports_for_update)

    def remove_port_filter(self, ports):
        LOG.info(_LI("Remove ports with rules"))
        for p_id in ports:
            port = self.dvs_ports.get(p_id)
            if port:
                self.remove_queue.put(port)
                self.dvs_ports.pop(p_id, None)

    @property
    def ports(self):
        return self.dvs_ports

    def _apply_sg_rules_for_port(self, ports):
        for port in ports:
            queue = self._get_free_queue()
            port = sg_util.filter_port_sg_rules_by_ethertype(port)
            queue.put([{'id': port['id'], 'network_id': port['network_id'],
                        'security_group_rules': port['security_group_rules'],
                        'binding:vif_details': port['binding:vif_details']}])

    def _get_free_queue(self):
        shortest_queue = self.list_queues[0]
        for queue in self.list_queues:
            queue_size = queue.qsize()
            if queue_size == 0:
                return queue
            if queue_size < shortest_queue.qsize():
                shortest_queue = queue
        return shortest_queue

    def update_security_group_rules(self, sg_id, sg_rules):
        pass

    def security_groups_provider_updated(self):
        LOG.info(_("Ignoring default security_groups_provider_updated RPC."))

    def update_security_group_members(self, sg_id, sg_members):
        pass

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        pass

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass
