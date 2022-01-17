# this is tcp proxy 
import sys
import socket
import threading

def server_loop(local_host,local_port,remote_host,remote_port,recevie_first):

	try:

		server.bind((local_host,local_port))

	except:

		print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
		print "[!!] Check for other listening sockets or correct permissions."
		sys.exit(0)

		print "[*] Listening on %s:%d" % (local_host,local_port)

	server.listen(5)

	while True:
		client_socket, addr = server.accept()

		# print out the local connection information
		print "[==>] Received incomming connections from %s:%d" % (addr[0],addr[1])

		# start a thread to talk to the remote host
		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket,remote_host,remote_port,recevie_first))

		proxy_thread.start()

def main():

	# no fancy command-line parsing here
	if len(sys.argv[1:]) !=5:
		print "Usage: ./proxy.py [localhost] [localport] ]remotehost] [remoteport] [recevie_first]"
		print "Examples: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
		sys.exit(0)

	# setup local listenting parameters
	local_host = sys.argv[1]
	local_port = int(sys.argv[2])

	# setup remote target
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])

	# this tells our proxy to connect and receive data before sending to the remote host
	recevie_first = sys.argv[5]

	if "True" in recevie_first:
		recevie_first = True
	else:
		recevie_first = False

	# now spin up our listening socket
	server_loop(local_host,local_port,remote_host,remote_port,recevie_first)

main()

def proxy_handler(client_socket, remote_host, remote_port, recevie_first):

	# connect to remote host
	remote_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	remote_socket.connect((remote_host,remote_port))

	# receive data from the remote end if necessary
	if recevie_first:

		remote_buffer = response_handler(remote_buffer)

		# if we have data to send to our loacl client, send it
		if len(remote_buffer):
			print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
			client_socket.send(remote_buffer)

		# now lets loop and read from local
		# send to remote, send to local
		# rinse, wash and repeat
		while True:

			# read from local host
			local_buffer = receive_from(client_socket)

			if len(local_buffer):

				print "[==>] Received %d bytes from localhost" % len(local_buffer)
				hexdump(local_buffer)

				# send to our request handler
				local_buffer = request_handler(local_buffer)

				# send off the data to the remote host
				remote_socket.send(local_buffer)
				print "[==>] Sent to remote."

				# receive back the response
				remote_buffer = receive_from(remote_socket)

				if len(remote_buffer):
					print "[<==] Received %d bytes from remote." % len(remote_buffer)
					hexdump(remote_buffer)

					# send to our response handler
					remote_buffer = response_handler(remote_buffer)

					# send the response to the local socket
					client_socket.send(remote_buffer)

					print "[<==] Sent to localhost."

				# if no more data on either side, close the connections
				if not len(local_buffer) or not len(remote_buffer):
					client_socket.close()
					remote_socket.close()
					print "[*] No more data. Closing connections."

					break

# this is a pretty hex dumping fuction directly taken from the comments here
# https://code.activerstate.com/recipes/142812-hex-dumper/
def hexdump(src, lenght=16):
	result = []
	digits = 4 if isinstance(src, unicode) else 2

	for i in xrange(0, len(src), lenght):
		s = src [i:i+lenght]
		hexa = b''.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
		result.append(b"%04X %-*s %s" % (i, lenght*(digits + 1), hexa,text))

	print b'\n'.join(result)


def receive_from(connection):
	buffer = ""

	# We set a 2 second timeout; depending on your
	# target this may need to be adjusted
	connection.settimeout(2)

	try:

		# keep reading into the buffer untill
		# there's no more data
		# or we time out
		while True:
			data = connection.recv(4096)

			if not data:
				break
			buffer += data

	except:
		pass

		return buffer

	# modify any requests destined for the remote host
def request_handler(buffer):
	# perfrom packet modications
	return buffer

# modify any response destined for the local host
def request_handler(buffer):
	# perform packets modications
	return buffer
	