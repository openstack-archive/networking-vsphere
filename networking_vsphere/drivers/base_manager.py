# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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


class DriverManager(object):

    '''Base class for all driver managers.'''

    def __init__(self):
        self.driver = None

    def get_driver(self):
        return self.driver

    def initialize_driver(self):
        '''Initialize the driver managed by this manager.'''
        raise NotImplementedError()

    def start(self):
        '''Start driver action when node is up.'''
        pass

    def pause(self):
        '''Handle pause action.'''
        pass

    def stop(self):
        '''Handle stop action.'''
        pass
