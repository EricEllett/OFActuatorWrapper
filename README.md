OFActuatorWrapper v.1
=================

A python wrapper for the [openflowsec.org's OFActuator](http://www.openflowsec.org/).

It primarily implements the following directives 
(excerpt from OFActuator_directives.txt bundled with Actuator itself):

* "BLOCK"      An alias for "DENY" (with different parameter names).
* "DENY"       Terminates all traffic matching specified criteria.
* "REDIRECT"   Redirects traffic for one host to another.
* "QUARANTINE" A form of "DENY" with web redirected to a notifier.
* "UNPLUG"     Shut down a specific port or the entire switch.

The remaining directives are used to diagnose and manage the actuator
and its active network security directives:

 * "ADJUST"   Adjust time-out of security directive.
 * "CANCEL"   Request removal of currently-active security directives.
 * "DEFAULTS" Sets and displays default values for the actuator.
 * "HELP"     Provides directive help-text.
 * "HOSTINFO" Provides information on hosts.
 * "INFO"     List active security directives.
 * "SHUTDOWN" Terminate the actuator.
 * "SWITCHES" Lists the switches managed by the controller.
 * "QUIT"     Disconnects the directive source issuing the directive
 See OFActuator_directives.txt for more information
 


Usage
==========
General usage requires instantiation of wrapper object

```python

From ActuatorWrapper import ActuatorWrapper

wrapper = ActuatorWrapper(<ACTUATOR_IP>, <ACTUATOR_PORT>)
```

Actuator ip:port defaults to localhost:26795 if not specified

Block
-----

Blocks all traffic matching specified criteria. (see OFActuator_directives.txt for more info)
Returns directive id.

####Example

```python
From ActuatorWrapper import ActuatorWrapper

wrapper = ActuatorWrapper(<ACTUATOR_IP>, <ACTUATOR_PORT>)
d_id = wrapper.block(blockIP="10.0.0.1", dstPort=22)
#SSH traffic eminating from 10.0.0.1 is now dropped at the SDN switch
...

wrapper.cancel(id=d_id)
#SSH from 10.0.0.1 is now unblocked
```

Possible parameters - blockIP, dstPort, proto, linkdrop, style, resetAfter, priority, switch, timeout

Please read the comments in the code and the OFActuator_directives.txt for instructions for the other directives.

