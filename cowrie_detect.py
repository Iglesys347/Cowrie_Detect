#!/usr/bin/python3

import paramiko, sys
import argparse
USER = "root"
PASSWORD = "123456"
score = 0
hostname = "localhost"

def connect_cowrie(host, usr, pwd):
	try:
		print("Connecting to {0} with username \"{1}\" and password \"{2}\"".format(host, usr, pwd))
		s = paramiko.SSHClient()
		s.load_system_host_keys()
		s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		s.connect(host, port=2222, username=usr, password=pwd)
		print("Executing commands...")
		(stdin, stdout, stderr) = s.exec_command("cat /etc/passwd")
		for line in stdout.readlines():
			if "phil" in line:
				print("[+5] User \"phil\" exists!")
				score += 5
		(stdin, stdout, stderr) = s.exec_command("cat /etc/shadow")
		for line in stdout.readlines():
			if "phil" in line:
				print("[+5] User \"phil\" exists!")
				score += 5
		s.close()
	except paramiko.ssh_exception.NoValidConnectionsError:
		print("Error: Could not connect to host!")
		sys.exit()
	except paramiko.ssh_exception.SSHException:
		print("Error: SSH connection error!")

def evaluation():
	print("Total Cowrie Score: " + str(score))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(usage='{0} [host] [options]'.format(sys.argv[0]))
	parser.add_argument("host", action='store', help="Host to connect to.")
	parser.add_argument("-u", "--username", action='store', default=USER, help="Connect using a specific username. Default is {0}.".format(USER))
	parser.add_argument("-p", "--password", action='store', default=PASSWORD, help="Connect using a specific password. Default is \"{0}\".".format(PASSWORD))
	args = parser.parse_args()
	lenargs = len(vars(args))

	# if lenargs < 3:
	# 	parser.print_help()
	# 	sys.exit()
	connect_cowrie(args.host, args.username, args.password)
	evaluation()