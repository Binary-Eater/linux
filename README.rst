TODO
====

WIP (stack)
-----------

 - uni-dir (raw UDP on one side)
 - packet drill

Future
------

 - assoc sharing
 - support binding PSD onto veth pairs

Feature
-------

 - inet diag support
 - support propagating PSD onto upper devices (*vlan)

Tests
-----

Functional:

 - disconnect

Perf:

 - C Rx alloc test
 - C RR test?
 - GRO

TODO
----

 - support rotation on a single connection
 - email: "psp packetdrill support"
 - document
 - look at Maxim's TLS workqueue rework
 - allow exposing more headers (ports, all L4, or L4 + fixed?)

Additional input:
 - support TIME_WAIT sockets
   - test it somehow
 - RCV.NXT for updade

 - MH support is required
 - key capacity query (for MH)
   - TBF for key allocation per cgroup

Bug
---
