## Any Variable names are currently just temporary while we decide what to call everything in the DB/Application
import subprocess
from subprocess import Popen, PIPE, run
import time

## Creates a rule pulling from database and input into UFW
def createRule( permission, protocol, from_ip, to_ip, port_number ):
	print ( "Create Rule" )
	##Verifies the firewall is running
	confirm = enableFirewall()
	if confirm != 0:
		return ret.returncode
	else:
		## command to add rule to UFW
		ret = subprocess.run( [ 'sudo', 'ufw', permission, 'from' , from_ip, 'proto', protocol,'to', to_ip, 'port', port_number ] )
		if ret.returncode == 0:
			return ret.returncode 
		else:
			return ret.returncode

## Pulls rule to be deleted from database and deletes from UFW
def deleteRule( permission, protocol, to_ip, from_ip, port_number ):
	print ( "Delete Rule" )
	##Verifies the firewall is running
	confirm = enableFirewall()
	if confirm != 0:
		return print ( "Firewall is not enabled" )
	else:
		##command to delete rule to UFW
		'''
		The UFW command needs a y|n input -> requires waiting.
		'''
		#port_number = int(port_number)
		ret = subprocess.run(['sudo', 'ufw', 'delete', permission, 'from', from_ip, 'proto', protocol, 'to', to_ip, 'port', port_number])
		print ( "ret = " + str (ret) + "\nret.returncode = " + str(ret.returncode) )
		if  ret.returncode == 0:
			print ( "IF After deletion" )
			return ret.returncode
		else:
			print ( "Else After deletion" )
			return ret.returncode

## Verifies that the firewall is running
def enableFirewall():
	print ( "Enable Firewall" )
	##Verify firewall is running using subprocess
	##ret is the object and returncode is a success or failure
	ret = subprocess.run([ 'sudo', 'ufw', 'enable' ])
	##returncode is 1 if error, 0 if succsseful
	if ret.returncode == 0:
		return 0
	else:
		return 1
