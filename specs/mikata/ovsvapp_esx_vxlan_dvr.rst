
======================================
OVSvApp SOLUTION: VXLAN + VXLAN + DVR
======================================

The br-int bridge, which is instantiated in the OVSvApp vm, will be leveraged
to support DVR and VXLAn on an ESXi Network.

The IR instantiated in the OVSvApp vm and will be attached to the br-int.

The external bridge (br-ex) will  provide connection to the external network
for north-south fip traffic.

+---------------------------------------------------------------------+
|        +-----------------------------+                              |
|        |         trunkport           |                              |
|        |                             |     OVSVAPP VM               |
|        |          br-sec             |                              |
|        |                             |                              |
|        |       patch+integration     |                              |
|        +-------------+---------------+                              |
|                      |                                              |
|                      |                                              |
|                      |                                              |
|        +-------------+---------------+                              |
|        |       patch-security        |   +-----------------+        |
|        |                             |   | Local instance  |        |
|        |         br-int              +---+ of DVR (IR)     |        |
|        |                             |   | (qr namespace)  |        |
|        |        patch-tun            |   +-------+---------+        |
|        +-------------+---------------+           |                  |
|                      |                  +--------+----------+       |
|                      |                  | FIP namespace     |       |
|                      |                  +--------+----------+       |
|        +-------------+---------------+           |                  |
|        |       patch-int             |      +----+-----+            |
|        |        br-tun               |      |          |            |
|        |                             |      |  br-ex   |            |
|        | Vxlan-xxx        Vxlan-yyy  |      |          |            |
|        +-----+---------------+-------+      +----+-----+            |
|              |               |                   |                  |
+---------------------------------------------------------------------+
               |               |                   |
   +-----------+------+ +------+----------+  +-----+------+
   |    Vxlan-zzz     | |    Vxlan-zzz    |  |  DVS to    |
   |                  | |                 |  |  external  |
   |    br-tun        | |     br-tun      |  |  network   |
   |(remote ovsvapp)  | | (remote ovsvapp)|  |            |
   +------------------+ +-----------------+  +------------+
