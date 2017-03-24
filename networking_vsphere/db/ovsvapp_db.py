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

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import common_db_mixin

from networking_vsphere._i18n import _, _LE, _LI, _LW
from networking_vsphere.db import ovsvapp_models as models
from networking_vsphere.extensions import ovsvapp_cluster
from networking_vsphere.extensions import ovsvapp_mitigated_cluster as vapp_mc

LOG = log.getLogger(__name__)

RETRY = "0"
GIVE_UP = "-1"
SUCCESS = "1"


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
    LOG.info(_LI("Finished initializing local vlans for cluster %(cluster)s "
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
            LOG.exception(_LE("Exception while initializing VNI "
                              "allocations for clusters %(cluster)s of "
                              "vCenter %(vcenter)s."),
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
                LOG.info(_LI("Assigned local vlan %(lvid)s for the network "
                             "%(network)s on the cluster %(cluster)s."),
                         {'network': port_info['network_id'],
                          'cluster': port_info['cluster_id'],
                          'lvid': lvid})
            else:
                LOG.error(_LE("All available VLANs are used up in the cluster "
                              "%(cluster)s of vCenter %(vcenter)s."),
                          {'cluster': res['cluster_id'],
                           'vcenter': res['vcenter_id']})
        except Exception as e:
            LOG.exception(_LE("Unable to obtain local vlan id %s."), e)
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
                LOG.info(_LI("Local VLAN rows not provisioned for the "
                             "cluster %(cluster)s of vCenter %(vcenter)s. "
                             "Going to provision."),
                         {'cluster': res['cluster_id'],
                          'vcenter': res['vcenter_id']})
        except Exception:
            LOG.exception(_LE("Error retrieving a local vlan for network "
                              "%(network)s for %(port)s."),
                          {'network': port_info['network_id'],
                           'port': port_info['port_id']})
            return
    status = _initialize_lvids_for_cluster(res)
    if status:
        with session.begin(subtransactions=True):
            lvid = _try_to_obtain_local_vlan(session, port_info, assign)
    else:
        LOG.error(_LE("Local VLAN rows not provisioned for the "
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
                LOG.info(_LI("lvid can be released for network: %s."), res)
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
                LOG.info(_LI("Released lvid for network: %s."), res)
            else:
                LOG.info(_LI("Unable to release local vlan for network_id %s "
                             "because ports are available on network."),
                         res['network_id'])
        except sa_exc.NoResultFound:
            # Nothing to do, may be another controller cleared the record
            # We will just log and return.
            LOG.error(_LE("Network %(network)s is already de-allocated for "
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
                LOG.info(_LI("Found stale allocations for network "
                             "%s."), network_id)
        except Exception:
            # Nothing to do, port-deletions have properly cleaned up
            # the records. We will just log and return back empty list.
            LOG.debug("Network %s is already cleaned up from "
                      "VNI allocations table.", network_id)
    return vcenter_clusters


def update_and_get_cluster_lock(vcenter_id, cluster_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = session.query(models.OVSvAppClusters)
            cluster_row = (query.filter(
                models.OVSvAppClusters.vcenter_id == vcenter_id,
                models.OVSvAppClusters.cluster_id == cluster_id
            ).with_lockmode('update').one())
            if not cluster_row.threshold_reached:
                if not cluster_row.being_mitigated:
                    cluster_row.update({'being_mitigated': True})
                    LOG.info(_LI("Blocked the cluster %s for maintenance."),
                             cluster_id)
                    return SUCCESS
                else:
                    LOG.info(_LI("Cluster %s is under maintenance. "
                                 "Will retry later"), cluster_id)
                    return RETRY
            else:
                LOG.warning(_LW("Cluster %(id)s in vCenter %(vc)s needs "
                                "attention. "
                                "Not able to put hosts to maintenance!"),
                            {'id': cluster_id,
                             'vc': vcenter_id})
                return GIVE_UP
        except sa_exc.NoResultFound:
            # First fault case in this cluster_id.
            cluster_row = {'vcenter_id': vcenter_id,
                           'cluster_id': cluster_id,
                           'being_mitigated': True}
            session.execute(models.OVSvAppClusters.__table__.insert(),
                            cluster_row)
            LOG.info(_LI("Blocked the cluster %s for maintenance."),
                     cluster_id)
            return SUCCESS


def release_cluster_lock(vcenter_id, cluster_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = session.query(models.OVSvAppClusters)
            cluster_row = (query.filter(
                models.OVSvAppClusters.vcenter_id == vcenter_id,
                models.OVSvAppClusters.cluster_id == cluster_id
            ).with_lockmode('update').one())
            cluster_row.update({'being_mitigated': False,
                                'threshold_reached': False})
        except sa_exc.NoResultFound:
            LOG.error(_LE("Cannot update the row for cluster %s."), cluster_id)


def reset_cluster_threshold(vcenter_id, cluster_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = session.query(models.OVSvAppClusters)
            cluster_row = (query.filter(
                models.OVSvAppClusters.vcenter_id == vcenter_id,
                models.OVSvAppClusters.cluster_id == cluster_id
            ).with_lockmode('update').one())
            if cluster_row.threshold_reached:
                cluster_row.update({'being_mitigated': False,
                                    'threshold_reached': False})
        except sa_exc.NoResultFound:
            # First agent in this cluster
            LOG.error(_LE("Cluster row not found for %s."), cluster_id)
            cluster_row = {'vcenter_id': vcenter_id,
                           'cluster_id': cluster_id}
            session.execute(models.OVSvAppClusters.__table__.insert(),
                            cluster_row)


def set_cluster_threshold(vcenter_id, cluster_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = session.query(models.OVSvAppClusters)
            cluster_row = (query.filter(
                models.OVSvAppClusters.vcenter_id == vcenter_id,
                models.OVSvAppClusters.cluster_id == cluster_id
            ).with_lockmode('update').one())
            LOG.info(_LI("Cluster row found for %s."), cluster_row)
            if not cluster_row.threshold_reached:
                cluster_row.update({'being_mitigated': False,
                                    'threshold_reached': True})
        except sa_exc.NoResultFound:
            LOG.error(_LE("Cluster row not found for %s."), cluster_id)


def _admin_check(context, action):
    """Admin role check helper."""
    if not context.is_admin:
        reason = _('Cannot %s resource for non admin tenant') % action
        raise exc.AdminRequired(reason=reason)


class OVSvAppClusterDbMixin(ovsvapp_cluster.OVSvAppClusterPluginBase):

    def get_ovsvapp_cluster(self, context, vcenter_id, fields=None):
        _admin_check(context, 'GET')
        LOG.info(_LI("Retrieving vCenter cluster information for vcenter_id:"
                     " %s."), vcenter_id)
        db_table = models.ClusterVNIAllocations
        query = context.session.query(db_table)
        filter_query = query.filter(db_table.vcenter_id == vcenter_id)
        grouped_query = filter_query.group_by('cluster_id')
        query_objs = grouped_query.all()
        if len(query_objs) == 0:
            _msg = ("No details found for vCenter:"
                    "%(vcenter_id)s") % {'vcenter_id': vcenter_id}
            raise exc.InvalidInput(error_message=_msg)
        vcenter_dict = dict()
        vcenter_dict['vcenter_id'] = vcenter_id
        vcenter_dict['clusters'] = [obj.cluster_id for obj in query_objs]
        return vcenter_dict

    def get_ovsvapp_clusters(self, context, filters=None, fields=None):
        _admin_check(context, 'GET')
        LOG.info(_LI("Retrieving vCenter cluster information."))
        if filters:
            if 'vcenter_id' in filters.keys():
                vcenter_id = filters['vcenter_id'][0]
                return [self.get_vcenter_cluster(context, vcenter_id)]
            _msg = "Invalid filter specified"
            raise exc.InvalidInput(error_message=_msg)
        query = context.session.query(models.ClusterVNIAllocations).group_by(
            'vcenter_id')
        query_objs = query.all()
        vcenter_set = set([vcenter.vcenter_id for vcenter in query_objs])
        vcenter_list = list()
        for vcenter in vcenter_set:
            filter_query = query.filter(models.ClusterVNIAllocations.
                                        vcenter_id == vcenter)
            grouped_objs = filter_query.group_by('cluster_id').all()
            vcenter_dict = dict()
            vcenter_dict['vcenter_id'] = vcenter
            vcenter_dict['clusters'] = [obj.cluster_id for obj in grouped_objs]
            vcenter_list.append(vcenter_dict)
        return vcenter_list

    def create_ovsvapp_cluster(self, context, ovsvapp_cluster):
        _admin_check(context, 'CREATE')
        vcenter = ovsvapp_cluster['ovsvapp_cluster']
        vcenter_clusters = vcenter['clusters']
        LOG.info(_LI("Creating a vCenter cluster entry with vcenter id %s."),
                 vcenter['vcenter_id'])
        for cluster_name in vcenter_clusters:
            vcenter_info = dict()
            vcenter_info['vcenter_id'] = vcenter['vcenter_id']
            vcenter_info['cluster_id'] = cluster_name
            if not _initialize_lvids_for_cluster(vcenter_info):
                raise exc.InvalidInput(error_message='Cannot create DB entry.')
        return vcenter

    def update_ovsvapp_cluster(self, context, id, ovsvapp_cluster):
        _admin_check(context, 'UPDATE')
        vcenter_id = id
        clusters_list = ovsvapp_cluster['ovsvapp_cluster']['clusters']
        LOG.info(_LI("Deleting the vCenter clusters %(cluster_id)s with"
                     "vCenter id %(vcenter_id)s."),
                 {'cluster_id': clusters_list,
                  'vcenter_id': id})
        with context.session.begin(subtransactions=True):
            query = context.session.query(models.ClusterVNIAllocations)
            for cluster_id in clusters_list:
                # Do a bulk delete operation with each cluster.
                query.filter(
                    models.ClusterVNIAllocations.vcenter_id == vcenter_id,
                    models.ClusterVNIAllocations.cluster_id == cluster_id
                ).delete()
        return ovsvapp_cluster['ovsvapp_cluster']


class OVSvAppMitigatedClusterDbMixin(vapp_mc.OVSvAppMitigatedClusterPluginBase,
                                     common_db_mixin.CommonDbMixin):

    def get_ovsvapp_mitigated_cluster(self, context, vcenter_id, fields=None):
        _admin_check(context, 'GET')
        mitigated_info = vcenter_id.split(':')
        vcenter_id = mitigated_info[0]
        cluster_id = mitigated_info[1].replace('|', '/')
        LOG.info(_LI("Retrieving mitigated information for vcenter_id"
                     " %s."), vcenter_id)
        mitigated_cluster = dict()
        try:
            query = context.session.query(models.OVSvAppClusters)
            cluster_row = (query.filter(
                models.OVSvAppClusters.vcenter_id == vcenter_id,
                models.OVSvAppClusters.cluster_id == cluster_id
            ).one())
        except sa_exc.NoResultFound:
            _msg = ("No entry found for specified vCenter %(vcenter_id)s "
                    "cluster %(cluster_id)s") % {'vcenter_id': vcenter_id,
                                                 'cluster_id': cluster_id}
            raise exc.InvalidInput(error_message=_msg)
        mitigated_cluster['vcenter_id'] = cluster_row.vcenter_id
        mitigated_cluster['cluster_id'] = cluster_row.cluster_id
        mitigated_cluster['being_mitigated'] = cluster_row.being_mitigated
        mitigated_cluster['threshold_reached'] = cluster_row.threshold_reached
        return mitigated_cluster

    def update_ovsvapp_mitigated_cluster(self, context, id,
                                         ovsvapp_mitigated_cluster):
        _admin_check(context, 'UPDATE')
        res_dict = ovsvapp_mitigated_cluster['ovsvapp_mitigated_cluster']
        vcenter_id = res_dict['vcenter_id']
        cluster_id = res_dict['cluster_id']
        update_flags = dict()
        if 'being_mitigated' in res_dict:
            update_flags['being_mitigated'] = res_dict['being_mitigated']
        if 'threshold_reached' in res_dict:
            update_flags['threshold_reached'] = res_dict['threshold_reached']
        LOG.error(_LE("Updating the mitigation properties with "
                      "vCenter id %s."),
                  vcenter_id)
        with context.session.begin(subtransactions=True):
            try:
                query = context.session.query(models.OVSvAppClusters)
                cluster_row = (query.filter(
                    models.OVSvAppClusters.vcenter_id == vcenter_id,
                    models.OVSvAppClusters.cluster_id == cluster_id
                ).with_lockmode('update').one())
                cluster_row.update(update_flags)
            except sa_exc.NoResultFound:
                _msg = ("No entry found for specified vCenter %(vcenter_id)s"
                        " cluster %(cluster_id)s") % {'vcenter_id': vcenter_id,
                                                      'cluster_id': cluster_id}
                raise exc.InvalidInput(error_message=_msg)
        return res_dict

    def get_ovsvapp_mitigated_clusters(self, context, filters=None,
                                       fields=None):
        _admin_check(context, 'GET')
        db_filters = dict()
        if filters:
            for filter_entry in filters:
                db_filters[filter_entry] = filters[filter_entry]
        LOG.info(_LI("Retrieving mitigated information of all clusters."))
        mitigated_clusters = list()
        try:
            all_entries = self._get_collection_query(context,
                                                     models.OVSvAppClusters,
                                                     filters=db_filters).all()
        except sa_exc.NoResultFound:
            raise exc.InvalidInput(error_message='Cannot retreive mitigated '
                                   'information.')
        for entry in all_entries:
            mitigated_cluster = dict()
            mitigated_cluster['vcenter_id'] = entry.vcenter_id
            mitigated_cluster['cluster_id'] = entry.cluster_id
            mitigated_cluster['being_mitigated'] = entry.being_mitigated
            mitigated_cluster['threshold_reached'] = entry.threshold_reached
            mitigated_clusters.append(mitigated_cluster)
        return mitigated_clusters

    def delete_ovsvapp_mitigated_cluster(self, context, id, filters=None):
        _admin_check(context, 'DELETE')
        mitigated_info = id.split(':')
        if len(mitigated_info) != 2:
            raise exc.InvalidInput(error_message='Invalid format..')
        vcenter_id = mitigated_info[0]
        cluster_id = mitigated_info[1].replace('|', '/')
        LOG.info(_LI("Deleting mitigation entry with vCenter_id %s."),
                 vcenter_id)
        with context.session.begin(subtransactions=True):
            try:
                query = context.session.query(models.OVSvAppClusters)
                query = query.filter(
                    models.OVSvAppClusters.vcenter_id == vcenter_id,
                    models.OVSvAppClusters.cluster_id == cluster_id
                ).delete()
            except sa_exc.NoResultFound:
                _msg = ("No entry found for specified vCenter %(vcenter_id)s"
                        " cluster %(cluster_id)s") % {'vcenter_id': vcenter_id,
                                                      'cluster_id': cluster_id}
                raise exc.InvalidInput(error_message=_msg)
