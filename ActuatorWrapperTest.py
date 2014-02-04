#!/usr/bin/python
# ActuatorWrapperTest.py - Test for Wrapper for openflowsec.org's OF-Actuator
# Works with Python 2.7. For 3 compatibility, unicode conversion required
# Written by Eric Ellett <eric.a.ellett@gmail.com>

"""
To run this test you must have se-floodlight.jar and the OFActuator.jar running,
you must also be running mininet (testing with 2.0) with a single switch
topology with 3 hosts. Mac field must also be set. Example mininet deployment
command (sudo mn --topo single,3 --mac).

If actuator is remote and/or using a different port, set the global variables 
SERVER_IP and SERVER_PORT accordingly.

Since command implementation is out of scope of the ActuatorWrapper, we only
test basic functionality

"""

import unittest
from ActuatorWrapper import ActuatorWrapper

SERVER_IP = "127.0.0.1"
SERVER_PORT = "26795"

class ActuatorWrapperTest(unittest.TestCase):

	@classmethod
	def setUpClass(cls):
		cls.wrapper = ActuatorWrapper(SERVER_IP, SERVER_PORT)

	@classmethod
	def tearDownClass(cls):
		cls.wrapper.cancel(all=True)
		cls.wrapper.quit()

	def test_block(self):
		""" Test normal BLOCK behavior. """
		d_id = self.wrapper.block(blockIP="10.0.0.1", resetAfter="1")
		self.wrapper.cancel(id=d_id)
		self.assertIs(type(d_id), int)

	def test_block_bad_params_1(self):
		""" Test BLOCK with bad parameters. Do not specify reqired blockIP. """
		self.assertRaises(ValueError, self.wrapper.block, resetAfter=1)

	def test_block_bad_params_2(self):
		""" Test BLOCK with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.block, blockIP="10.0.0.1",
						  test=1)

	def test_deny(self):
		""" Test normal DENY behavior. """
		d_id = self.wrapper.deny(IP1="10.0.0.2", resetAfter="1")
		self.wrapper.cancel(id=d_id)
		self.assertIs(type(d_id), int)

	def test_deny_bad_params_1(self):
		""" 
		Test DENY with bad parameters. Do not specify one of first 4 criteria.
		"""
		self.assertRaises(ValueError, self.wrapper.deny, resetAfter=1)

	def test_deny_bad_params_2(self):
		""" Test DENY with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.deny, test=1)

	def test_redirect(self):
		""" Test normal REDIRECT behavior. """
		d_id = self.wrapper.redirect(IP1="10.0.0.1", remapIP="10.0.0.2", 
									resetAfter="1")
		self.wrapper.cancel(id=d_id)
		self.assertIs(type(d_id), int)

	def test_redirect_bad_params_1(self):
		""" 
		Test REDIRECT with bad parameters. Do not specify required remapIP.
		"""
		self.assertRaises(ValueError, self.wrapper.redirect, resetAfter=1)

	def test_redirect_bad_params_2(self):
		""" Test REDIRECT with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.redirect, test=1)

	def test_quarantine(self):
		""" Test normal QUARANTINE behavior. """
		d_id = self.wrapper.quarantine(quarantinedIP="10.0.0.1", 
										notifier="10.0.0.2", resetAfter="1")
		self.wrapper.cancel(id=d_id)
		self.assertIs(type(d_id), int)

	def test_quarantine_bad_params_1(self):
		""" 
		Test QUARANTINE with bad parameters. Do not specify required 
		quarantinedIP or notifier
		"""
		self.assertRaises(ValueError, self.wrapper.quarantine, resetAfter=1)

	def test_quarantine_bad_params_2(self):
		""" Test QUARANTINE with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.quarantine, 
						  quarantinedIP="10.0.0.1", Notifier="10.0.0.2",test=1)

	
	""" Does not work with default switch bundled with mininet """
	# def test_unplug(self):
	# 	""" Test normal UNPLUG behavior. """
	# 	d_id = self.wrapper.unplug(IP="10.0.0.1")
	# 	self.wrapper.cancel(id=d_id)
	# 	self.assertIs(type(d_id), int)

	def test_unplug_bad_params_1(self):
		""" 
		Test UNPLUG with bad parameters. Do not specify exactly
		one of first 4 criteria.
		"""
		self.assertRaises(ValueError, self.wrapper.unplug, resetAfter=1)

	def test_unplug_bad_params_2(self):
		""" Test UNPLUG with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.unplug, test=1)

	def test_info(self):
		""" Test normal INFO behavior. """
		d_str = self.wrapper.info(rules=True)
		self.assertIn("DONE", d_str)
		
	def test_info_bad_params_1(self):
		"""	Test INFO with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.info, test=1)

	def test_cancel(self):
		""" Test normal CANCEL behavior. """
		d_str = self.wrapper.cancel(all=True)
		self.assertEqual(d_str, True)

	def test_cancel_bad_params_1(self):
		""" 
		Test CANCEL with bad parameters. Specify both parameters when expecting
		exactly 1.
		"""
		self.assertRaises(ValueError, self.wrapper.cancel, all=True, id=0)

	def test_cancel_bad_params_2(self):
		""" 
		Test CANCEL with bad parameters. Specify neither parameters when 
		expecting exactly 1.
		"""
		self.assertRaises(ValueError, self.wrapper.cancel)

	def test_cancel_bad_params_3(self):
		""" Test CANCEL with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.cancel, test=1)

	def test_adjust(self):
		""" Test normal ADJUST behavior. """
		d_id = self.wrapper.block(blockIP="10.0.0.1", resetAfter="5")
		self.assertIs(type(d_id), int)
		d_bool = self.wrapper.adjust(id=d_id, timeout="10")
		self.wrapper.cancel(id=d_id)
		self.assertEqual(d_bool, True)
		
	def test_adjust_bad_params_1(self):
		""" Test ADJUST with bad parameters. Do not specify both reqired params 
			id or timeout
		"""
		self.assertRaises(ValueError, self.wrapper.adjust)

	def test_adjust_bad_params_2(self):
		""" Test ADJUST with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.adjust, test=1)

	def test_switches_1(self):
		""" Test SWITCHES switches behavior without verbosity. """
		d_str = self.wrapper.switches()
		self.assertIn("DONE", d_str)

	def test_switches_2(self):
		""" Test SWITCHES switches behavior with verbosity. """
		d_str = self.wrapper.switches(v=True)
		self.assertIn("DONE", d_str)

	def test_switches_bad_params_1(self):
		""" Test SWITCHES with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.switches, test=1)

	def test_defaults(self):
		""" Test normal DEFAULTS behavior. """
		d_str = self.wrapper.defaults(timeout=5)
		self.assertEqual(d_str, True)

	def test_defaults_bad_params_1(self):
		""" Test DEFAULTS with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.defaults, test=0)

	def test_help(self):
		""" Test normal HELP behavior. """
		d_str = self.wrapper.help()
		self.assertIn("DONE", d_str)

	def test_help_bad_params_1(self):
		""" Test HELP with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.help, test=0)

	def test_hostinfo(self):
		""" Test normal HOSTINFO behavior. """
		d_str = self.wrapper.hostinfo()
		self.assertIn("DONE", d_str)

	def test_hostinfo_bad_params_1(self):
		""" Test HOSTINFO with bad parameters. """
		self.assertRaises(ValueError, self.wrapper.hostinfo, test=0)

	def test_hostinfo(self):
		""" Test normal HOSTINFO behavior. """
		temp_wrapper = ActuatorWrapper(SERVER_IP, SERVER_PORT)
		d_bool = temp_wrapper.quit()
		self.assertEqual(True, d_bool)
	

if __name__ == '__main__':
	unittest.main()