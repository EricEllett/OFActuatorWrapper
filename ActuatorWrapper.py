#!/usr/bin/python
# ActuatorWrapper.py - Wrapper for openflowsec.org's OF-Actuator
# Works with Python 2.7. For 3 compatibility, unicode conversion required
# Written by Eric Ellett <eric.a.ellett@gmail.com>

"""
This program creates a python wrapper around openflowsec.org's OF-Actuator. 
It primarily implements the following directives 
(exceprt from OFActuator_directives.txt):

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
 
 Please note that some function descriptions were taken directly from 
 OFActuator_directives.txt
 """
__version__ = '0.1'

import re
import socket
from time import sleep

class ActuatorWrapper:
	""" A simple wrapper class for the openflowsec.org's OF-Actuator"""

	def __init__(self, server_ip="127.0.0.1", server_port=26795):
		self._server_ip = server_ip
		self._server_port = server_port
		self._conn = self._init_server_conn()

	def _init_server_conn(self):
		"""
		Init server and return create_connection
		"""
		#Let default socket exception be thrown back to user
		conn = socket.create_connection((self._server_ip, self._server_port))
	
		return conn

	def _send_command(self, directive):
		"""
		Send directive string to server and return response
		"""
		#Check for ASCII encoding
		if type(directive) != str:
			raise ValueError("Directive must be in ASCII")
		if not self._conn:
			self.restart_server_conn()
		self._conn.send(directive + "\n")
		data = ""
		#QUIT closes socket and expects no response
		if "QUIT" not in directive:
			while 1:
				data = self._conn.recv(1024)
				if any(word in data for word in ["OK", "DONE", "ERROR", "echo"]):
					break

		if re.match("ERROR", data):
			raise Exception(data)

		return data

	def restart_server_conn(self, server_ip = None, server_port = None):
		"""
		Restarts the server connection to previous or new address
		"""

		self._server_ip = server_ip if server_ip else self._server_ip
		self._server_port = server_port if server_port else self._server_port
		self._conn = init_server_conn()


	def _generate_args(self, poss_params, **kwargs):
		"""
		Create directive addon string out of kwargs
		"""		
		args_gen = " "
		for param, value in kwargs.iteritems():
			param = str(param)
			if param not in poss_params:
				raise ValueError(("Parameter \"" + param + "\" not in possible "
							"parameter set for this Directive. Possible "
							"parameters are - " + " ".join(poss_params)))
			#If argument is a bool, simply add the '-param' to the string
			if type(value) == bool and value == True:
				args_gen += "-" + str(param) + " "
			else:
				args_gen += "-" + str(param) + " " + str(value) + " "
		
		return args_gen.rstrip()

	def _extract_directive_id(self, data):
		""" 
		Retrieve directive id from Actuator response
		"""
		dir_id = re.match(r"OK (\d+)", str(data))
		if not dir_id:
			raise ValueError(("Data received did not contain directive "
							  "identifier, instead received: \"" + data + "\"" ))
		return int(dir_id.group(1))

	def block(self, **kwargs):
		"""
		ARGUMENTS:
			o   -blockIP <CIDR>
			o  [-dstPort <port>         ]
			o  [-proto <protocol>       ]
			o  [-linkdrop <True/False>  ]
			o  [-style <style>          ]
			o  [-resetAfter <seconds>   ]
			o  [-priority <N>           ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]
		
		DESCRIPTION: Blocks all traffic matching specified criteria.
			This directive is translated into the equivalent DENY directive:
			DENY -IP1 <CIDR> [ -IP2port <port> ] ...options...
			Note: "-linkdrop" becomes "-linkdrop1"

		RETURNS:
			@rtype: Integer
			@return: Directive ID
		"""
		poss_params = ["blockIP", "dstPort", "proto", "linkdrop", "style",
						"resetAfter", "priority", "switch", "timeout"]

		if kwargs.get("blockIP") == None:
			raise ValueError("blockIP must be specified")

		cmd_string = ("BLOCK" + self._generate_args(poss_params, **kwargs))
		data = self._send_command(cmd_string)
		return self._extract_directive_id(data)

	def deny(self, **kwargs):
		"""
		ARGUMENTS: (at least one of the first four criteria required)
			o  [-IP1 <CIDR>             ]
			o  [-IP2 <CIDR>             ]
			o  [-IP1port <port>         ]
			o  [-IP2port <port>         ]
			o  [-proto <protocol>       ]
			o  [-linkdrop1 <True/False> ]
			o  [-linkdrop2 <True/False> ]
			o  [-style <style>          ]
			o  [-resetAfter <seconds>   ]
			o  [-priority <N>           ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]
		
		DESCRIPTION: Blocks all traffic matching specified criteria.
			Blocks (drops) all IP traffic to/from IP1-CIDR/IP1-port (from/to
			IP2-CIDR/IP2-port)...
			NOTE: See OFActuator_directives.txt for more info

		RETURNS:
			@rtype: Integer
			@return: Directive ID
		"""
		poss_params = ["IP1", "IP2", "IP1port", "IP2port", "proto", "linkdrop1",
					   "linkdrop2", "style", "resetAfter", "priority", "switch",
					   "timeout"]

		#Who needs short circuits???
		if all([kwargs.get("IP1") == None, kwargs.get("IP2") == None, 
				kwargs.get("IP1port") == None, 
				kwargs.get("IP2port") == None]):
			raise ValueError(("You must specify at least one of the parameters:"
							  " IP1, IP2, IP1port, IP2port"))

		cmd_string = "DENY" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return self._extract_directive_id(data)


	def redirect(self, **kwargs):
		"""
		ARGUMENTS: (at least one of the first four criteria required)
			o  [-IP1 <CIDR>             ]
			o  [-IP2 <CIDR>             ]
			o  [-IP1port <port>         ]
			o  [-IP2port <port>         ]
			o  [-proto <protocol>       ]
			o   -remapIP <IP>
			o  [-remapPort <port>       ]
			o  [-block <style>          ]
			o  [-resetAfter <seconds>   ]
			o  [-redirectIdle <seconds> ]
			o  [-priority <N>           ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]
		
		DESCRIPTION: Redirect matching network traffic to remapIP address (and 
			port). This directive will rewrite any traffic from IP1/port to 
			IP2/port as traffic from IP1/port to remapIP/port and DENY matching 
			traffic from IP2/port to IP1/port.  Further, any IP1/port to 
			IP2/port traffic from pre-existing TCP connections will be blocked 
			as per <style>.
			NOTE: See OFActuator_directives.txt for more info

		RETURNS:
			@rtype: Integer
			@return: Directive ID

		"""
		poss_params = ["IP1", "IP2", "IP1port", "IP2port", "proto", "remapIP", 
					   "remapPort", "block", "resetAfter", "redirectIdle",
					   "priority", "switch", "timeout"]

		#Probably a better way to format this
		if (kwargs.get("remapIP") == None or 
			all([	kwargs.get("IP1") == None, kwargs.get("IP2") == None, 
					kwargs.get("IP1port") == None, 
					kwargs.get("IP2port") == None])):
			raise ValueError(("You must specify remapIP and at least one of "
							  "the parameters: ip1, ip2, ip1_port, ip2_port as "
							  "well as remapIP"))

		cmd_string = "REDIRECT" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return self._extract_directive_id(data)

	def quarantine(self, **kwargs):
		"""
		ARGUMENTS: 
			o   -quarantinedIP <IP>
			o   -notifier <IP>
			o  [-notifierPort <port>    ]
			o  [-dnsIP <IP>             ]
			o  [-dnsPass <True/False>  	]
			o  [-linkdrop <True/False>	]
			o  [-style <style>          ]
			o  [-resetAfter <seconds>   ]
			o  [-redirectIdle <seconds> ]
			o  [-priority <N>           ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]
		
		DESCRIPTION: 
			Drop quarantined IP off the network; redirect web/DNS.
			Blocks all general traffic through the switch to/from the 
			quarantined IP address, with the exception that all DNS requests 
			will be redirected to the dnsIP (default: notifier's IP addr) and 
			all web (port 80) requests will be redirected to the notifier's 
			IP/port (allows the notifier to return web pages informing the user
			of the quarantine, providing remediationi nstructions, requesting 
			the user to contact administrative support, etc.).
			NOTE: See OFActuator_directives.txt for more info

		RETURNS:
			@rtype: Integer
			@return: Directive ID

		"""
		poss_params = ["quarantinedIP", "notifier", "notifierPort", "dnsIP", 
						"dnsPass", "linkdrop", "style", "resetAfter", 
						"redirectIdle", "priority", "switch", "timeout"]

		if any([kwargs.get("quarantinedIP") == None, 
				kwargs.get("notifier") == None]):
			raise ValueError(("You must specify quarantinedIP and notifier"))

		cmd_string = "QUARANTINE" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return self._extract_directive_id(data)

	def unplug(self, **kwargs):
		"""
		ARGUMENTS: 
			o  [-all <True/False        ]
			o  [-IP <IP>                ]
			o  [-linkAddr <MAC>         ]
			o  [-swPort <n>             ]
			o  [-priority <N>           ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]		
		DESCRIPTION: 
			Drop packets on one or more switch ports.
			NOTE: See OFActuator_directives.txt for more info

		RETURNS:
			@rtype: Integer
			@return: Directive ID

		"""
		poss_params = ["all", "IP", "linkAddr", "swPort", "priority", "switch",
					   "timeout"]

		if sum([kwargs.get("all") == None, kwargs.get("IP") == None, 
				kwargs.get("linkAddr") == None, 
				kwargs.get("swPort") == None]) != 3:
			raise ValueError(("Exactly one of all, ip, linkAddr, or swPort must" 
							  " be specified."))

		cmd_string = "UNPLUG" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return self._extract_directive_id(data)

	def info(self, **kwargs):
		"""
		ARGUMENTS: 
			o  [-id <N> 			]
			o  [-rules <True/False> ]	
		DESCRIPTION:
			List active security directives.
			The INFO command allows you to ask the actuator for the disposition 
			of all active (i.e., not-expired) security directives.  If the -id 
			parameter is specified, then only its associated security directive 
			is displayed.
			NOTE: See OFActuator_directives.txt for more info

		RETURNS:
			@rtype: return
			@String: One directive per line format: 
				" <id>: <directive>; <expires>" 

		"""
		poss_params = ["id", "rules"]

		cmd_string = "INFO" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return data

	def cancel(self, **kwargs):
		"""
		ARGUMENTS:
			o  [-all <True/False>   ]
			o  [-id <N> ]
		DESCRIPTION:   Request removal of currently-active security directives.
			Remove all flow mods associated with the security directive(s) or 
			otherwise removes the effects of the directive on the switch (e.g., 
			for "UNPLUG" re-activates the switch port).  If "-all" is specified,
			all directives are removed.  If "-id <N>" is specified, the 
			specified directive is removed. It is an error to specify both.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: Boolean
			@return: True if directive succeeds
		"""
		poss_params = ["all", "id"]

		if sum([kwargs.get("all") == None, kwargs.get("id") == None]) != 1:
			raise ValueError("You must specify either all or id")

		cmd_string = "CANCEL" + self._generate_args(poss_params, **kwargs)
		self._send_command(cmd_string)
		return True

	def adjust(self, **kwargs):
		"""
		ARGUMENTS:
			o   -id <N>
			o   -timeout <seconds>
		DESCRIPTION:   Adjust time-out of security directive.
			Will adjust the timeout of a currently-active security directive to 
			at least <seconds> from the time the directive is processed by the 
			actuator.  This can either lengthen or shorten the expiration of the
			affected directive.  As	with directive creation, a value of zero 
			means the directive remains active indefinitely.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: Boolean
			@return: True if directive succeeds
		"""
		poss_params = ["id", "timeout"]
		
		if kwargs.get("id") == None or kwargs.get("timeout") == None:
			raise ValueError("You must specify id and timeout")

		cmd_string = "ADJUST" + self._generate_args(poss_params, **kwargs)
		self._send_command(cmd_string)
		return True

	def switches(self, **kwargs):
		"""
		ARGUMENTS:
			o [ -v <True/False>]
		DESCRIPTION:   Lists the switches managed by the controller.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: String
			@return: List of switches managed by the controller
		"""
		poss_params = ["v"]

		cmd_string = "SWITCHES" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return data

	def defaults(self, **kwargs):
		"""
		ARGUMENTS:
			o  [-priority <N>           ]
			o  [-redirectIdle <seconds> ]
			o  [-resetAfter <seconds>   ]
			o  [-switch <switch-id>     ]
			o  [-timeout <seconds>      ]
		DESCRIPTION:   Sets and displays default values for the actuator.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: Boolean
			@return: True if directive succeeds
		"""
		poss_params = ["priority", "redirectIdle", "resetAfter", "switch", 
					   "timeout"]

		cmd_string = "DEFAULTS" + self._generate_args(poss_params, **kwargs)
		self._send_command(cmd_string)
		return True

	def shutdown(self):
		"""
		ARGUMENTS: none
		DESCRIPTION:   Terminate the actuator. Perform a "CANCEL -all" and 
				shut down the actuator process.
				NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: Boolean
			@return: True if directive succeeds
		"""
		cmd_string = "SHUTDOWN"
		self._send_command(cmd_string)
		return True

	def help(self, **kwargs):
		"""
		ARGUMENTS:
			o  [<directive-name>     ]
		DESCRIPTION:   Provides directive help-text.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: String
			@return: If <directive-name> is provided and is a known directive, 
				displays extended help-text for the directive.  Otherwise a 
				usage summary for each directive is displayed.
		"""
		poss_params = ["directive-name"]

		cmd_string = "HELP" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return data

	def hostinfo(self, **kwargs):
		"""
		ARGUMENTS:
			o  [-IP <IP>                ]
		DESCRIPTION:   Provides information on hosts.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: String
			@return: If <IP> is provided, performs a host look-up query and 
				returns known information about that host (MAC address, switch 
				path ID and port number). Otherwise (if <IP> is not provided), 
				returns known information about all hosts in the local cache.
		"""
		poss_params = ["IP"]

		cmd_string = "HOSTINFO" + self._generate_args(poss_params, **kwargs)
		data = self._send_command(cmd_string)
		return data

	def quit(self):
		"""
		ARGUMENTS: none
		DESCRIPTION:   Disconnects the directive source issuing the directive.
			NOTE: See OFActuator_directives.txt for more info
		RETURNS:
			@rtype: Boolean
			@return: True if directive succeeds
		"""
		cmd_string = "QUIT"
		self._send_command(cmd_string)
		self._conn = None
		return True

	def close(self):
		""" Utility function for "with" blocks """
		self.quit()
