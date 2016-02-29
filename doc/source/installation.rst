============
Installation
============

At the command line::

    $ pip install networking-vsphere

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv networking-vsphere
    $ pip install networking-vsphere

If you want to use the vmware-dvs driver you shoud patch nova by file
nova.patch in the data directory.
