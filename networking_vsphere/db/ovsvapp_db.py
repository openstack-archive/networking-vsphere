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

from oslo_log import log
import sqlalchemy.orm.exc as sa_exc

from neutron.db import api as db_api

from networking_vsphere.db import ovsvapp_models as models

LOG = log.getLogger(__name__)


def _generate_vcenter_cluster_allocations(session, vcenter, cluster):
    bulk_size = 100
    allocs = []
    lvid_min = 1
    lvid_max = 4095

    for lvid in range(lvid_min, lvid_max):
        allocs.append({'vcenter_id': vcenter,
                       'cluster_id': cluster,
                       'lvid': lvid})
    if allocs:
        chuncked_allocs = (allocs[i:i + bulk_size] for i in
                           range(0, len(allocs), bulk_size))
        for bulk in chuncked_allocs:
            session.execute(models.ClusterVNIAllocations.
                            __table__.insert(), bulk)
    LOG.info(_("Finished initializing local vlans for cluster %(cluster)s "
               "of vCenter %(vcenter)s."), {'cluster': cluster,
                                            'vcenter': vcenter})


def _initialize_lvids_for_cluster(port_info):
    vcenter = port_info['vcenter_id']
    cluster = port_info['cluster_id']
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            (session.query(models.ClusterVNIAllocations).
             with_lockmode('update')).all()
            query = session.query(models.ClusterVNIAllocations)
            existing_allocations = query.filter(
                models.ClusterVNIAllocations.vcenter_id == vcenter,
                models.ClusterVNIAllocations.cluster_id == cluster
            ).all()
            if not existing_allocations:
                _generate_vcenter_cluster_allocations(
                    session, vcenter, cluster)
            return True
        except Exception:
            LOG.exception(_("Exception while initializing VNI allocations for "
                            "clusters %(cluster)s of vCenter %(vcenter)s."),
                          {'cluster': cluster,
                           'vcenter': vcenter})
            return False


def _try_to_obtain_local_vlan(session, port_info, assign):
    lvid = None
    res_keys = ['vcenter_id', 'cluster_id', 'network_id']
    res = dict((k, port_info[k]) for k in res_keys)
    try:
        allocation = (session.query(models.ClusterVNIAllocations).filter(
            models.ClusterVNIAllocations.vcenter_id == res['vcenter_id'],
            models.ClusterVNIAllocations.cluster_id == res['cluster_id'],
            models.ClusterVNIAllocations.network_id == res['network_id']
        ).one())
        lvid = allocation.lvid
        if assign:
            count = allocation.network_port_count + 1
            allocation.update({'network_port_count': count})
            LOG.debug("Incremented the allocated port count for network "
                      "%s.", res)
    except sa_exc.NoResultFound:
        if not assign:
            raise Exception()
        try:
            allocation = session.query(models.ClusterVNIAllocations).filter(
                models.ClusterVNIAllocations.vcenter_id == res['vcenter_id'],
                models.ClusterVNIAllocations.cluster_id == res['cluster_id'],
                models.ClusterVNIAllocations.allocated == 0
            ).first()
            if allocation:
                lvid = allocation.lvid
                allocation.update({'network_id': res['network_id'],
                                   'allocated': True,
                                   'network_port_count': 1})
                LOG.info(_("Assigned local vlan %(lvid)s for the network "
                           "%(network)s on the cluster %(cluster)s."),
                         {'network': port_info['network_id'],
                          'cluster': port_info['cluster_id'],
                          'lvid': lvid})
            else:
                LOG.error(_("All available VLANs are used up in the cluster "
                            "%(cluster)s of vCenter %(vcenter)s."),
                          {'cluster': res['cluster_id'],
                           'vcenter': res['vcenter_id']})
        except Exception as e:
            LOG.exception(_("Unable to obtain local vlan id %s."), e)
    return lvid


def get_local_vlan(port_info, assign=True):
    lvid = None
    session = db_api.get_session()
    res_keys = ['vcenter_id', 'cluster_id', 'network_id']
    res = dict((k, port_info[k]) for k in res_keys)
    with session.begin(subtransactions=True):
        try:
            if not assign:
                lvid = _try_to_obtain_local_vlan(session, port_info, assign)
                return lvid
            query = session.query(models.ClusterVNIAllocations)
            # Lock all the rows in the table corresponding to the vCenter
            # and cluster.
            cluster_rows = query.filter(
                (models.ClusterVNIAllocations.vcenter_id == res['vcenter_id']),
                (models.ClusterVNIAllocations.cluster_id == res['cluster_id'])
            ).with_lockmode('update').all()
            if cluster_rows:
                lvid = _try_to_obtain_local_vlan(session, port_info, assign)
                return lvid
            else:
                LOG.info(_("Local VLAN rows not provisioned for the "
                           "cluster %(cluster)s of vCenter %(vcenter)s. "
                           "Going to provision."),
                         {'cluster': res['cluster_id'],
                          'vcenter': res['vcenter_id']})
        except Exception:
            LOG.exception(_("Error retrieving a local vlan for network "
                            "%(network)s for %(port)s."),
                          {'network': port_info['network_id'],
                           'port': port_info['port_id']})
            return
    status = _initialize_lvids_for_cluster(res)
    if status:
        with session.begin(subtransactions=True):
            lvid = _try_to_obtain_local_vlan(session, port_info, assign)
    else:
        LOG.error(_("Local VLAN rows not provisioned for the "
                    "cluster %(cluster)s of vCenter %(vcenter)s."),
                  {'cluster': res['cluster_id'],
                   'vcenter': res['vcenter_id']})
    return lvid


def check_to_reclaim_local_vlan(port_info):
    lvid = -1
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        res_keys = ['vcenter_id', 'cluster_id', 'network_id']
        res = dict((k, port_info[k]) for k in res_keys)
        try:
            query = session.query(models.ClusterVNIAllocations)
            allocation = (query.filter(
                models.ClusterVNIAllocations.vcenter_id == res['vcenter_id'],
                models.ClusterVNIAllocations.cluster_id == res['cluster_id'],
                models.ClusterVNIAllocations.network_id == res['network_id']
            ).with_lockmode('update').one())
            count = allocation.network_port_count
            if count >= 1:
                count -= 1
                allocation.update({'network_port_count': count})
                LOG.debug("Decremented the allocated port count for network "
                          "%s.", res)
            if count == 0:
                lvid = allocation.lvid
                LOG.info(_("lvid can be released for network: %s."), res)
        except sa_exc.NoResultFound:
            # Nothing to do, may be another controller cleared the record
            # We will just log and return back status as False.
            LOG.debug("Network %(network)s is already de-allocated for "
                      "cluster %(cluster)s.",
                      {'network': port_info['network_id'],
                       'cluster': port_info['cluster_id']})
    return lvid


def release_local_vlan(net_info):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        res_keys = ['vcenter_id', 'cluster_id', 'network_id']
        res = dict((k, net_info[k]) for k in res_keys)
        try:
            query = session.query(models.ClusterVNIAllocations)
            allocation = (query.filter(
                models.ClusterVNIAllocations.vcenter_id == res['vcenter_id'],
                models.ClusterVNIAllocations.cluster_id == res['cluster_id'],
                models.ClusterVNIAllocations.network_id == res['network_id']
            ).with_lockmode('update').one())
            if allocation.network_port_count == 0:
                allocation.update({'network_id': None,
                                   'allocated': False,
                                   'network_port_count': 0})
                LOG.info(_("Released lvid for network: %s."), res)
            else:
                LOG.info(_("Unable to release local vlan for network_id %s "
                           "because ports are available on network."),
                         res['network_id'])
        except sa_exc.NoResultFound:
            # Nothing to do, may be another controller cleared the record
            # We will just log and return.
            LOG.error(_("Network %(network)s is already de-allocated for "
                        "cluster %(cluster)s."),
                      {'network': net_info['network_id'],
                       'cluster': net_info['cluster_id']})


def get_stale_local_vlans_for_network(network_id):
    session = db_api.get_session()
    vcenter_clusters = None
    with session.begin(subtransactions=True):
        try:
            query = session.query(models.ClusterVNIAllocations)
            allocations = (query.filter(
                models.ClusterVNIAllocations.network_id == network_id
            ).all())
            if allocations:
                vcenter_clusters = []
                for alloc in allocations:
                    vcenter_clusters.append((alloc.vcenter_id,
                                             alloc.cluster_id,
                                             alloc.lvid))
                LOG.info(_("Found stale allocations for network "
                           "%s."), network_id)
        except Exception:
            # Nothing to do, port-deletions have properly cleaned up
            # the records. We will just log and return back empty list.
            LOG.debug("Network %s is already cleaned up from "
                      "VNI allocations table.", network_id)
    return vcenter_clusters
