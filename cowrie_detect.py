#!/usr/bin/python3

import paramiko, sys
import argparse
import re
import os
import urllib.request
import string
USER = "root"
PASSWORD = "password"
score = 0
PORT = 2222

##########################################################
# ShellHandler class made by misha at Stack Overflow (https://stackoverflow.com/questions/35821184/implement-an-interactive-shell-over-ssh-in-python-using-paramiko)
class ShellHandler:

	def __init__(self, host, prt, user, psw):
		self.ssh = paramiko.SSHClient()
		self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		self.ssh.connect(host, username=user, password=psw, port=prt)

		channel = self.ssh.invoke_shell()
		self.stdin = channel.makefile('wb')
		self.stdout = channel.makefile('r')

	def __del__(self):
		self.ssh.close()

	def execute(self, cmd):
		"""

		:param cmd: the command to be executed on the remote computer
		:examples:  execute('ls')
					execute('finger')
					execute('cd folder_name')
		"""
		cmd = cmd.strip('\n')
		self.stdin.write(cmd + '\n')
		finish = "end of stdOUT buffer. finished with exit status"
		echo_cmd = 'echo {} $?'.format(finish)
		self.stdin.write(echo_cmd + '\n')
		shin = self.stdin
		self.stdin.flush()

		shout = []
		sherr = []
		exit_status = 0
		for line in self.stdout:
			line = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).replace('\b', '').replace('\r', '')
			if line.startswith(cmd) or str(line).startswith(echo_cmd):
				# up for now filled with shell junk from stdin
				shout = []
			elif str(line).startswith(finish):
				# our finish command ends with the exit status
				exit_status = int(str(line).rsplit(maxsplit=1)[1])
				if exit_status:
					# stderr is combined with stdout.
					# thus, swap sherr with shout in a case of failure.
					sherr = shout
					shout = []
				break
			else:
				# get rid of 'coloring and formatting' special characters
				shout.append(re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).
							 replace('\b', '').replace('\r', ''))

		# first and last lines of shout/sherr contain a prompt
		if shout and echo_cmd in shout[-1]:
			shout.pop()
		if shout and cmd in shout[0]:
			shout.pop(0)
		if sherr and echo_cmd in sherr[-1]:
			sherr.pop()
		if sherr and cmd in sherr[0]:
			sherr.pop(0)

		return shin, shout, sherr
##########################################################

def getoui():
	print("Retrieving a sanitized OUI file from \"https://linuxnet.ca/\".")
	print("This may take a minute.")
	try:
		urllib.request.urlretrieve("https://linuxnet.ca/ieee/oui.txt", filename="oui.txt")
		return 0
	except Exception:
		print("Could not retrieve the OUI file. Skipping MAC address testing.")
		return 1

def generate_oui():
	if os.path.isfile("oui.txt"): # Check if the oui.txt file exists in the same directory as the script.
		parsebool = ""
		print("An oui file has been found. Use this file to test or retrieve a new one?")
		while parsebool != 'p' and parsebool != 'r':
			parsebool = input("Input (p/r):")
			parsebool.lower()
		if parsebool == 'r':
			if getoui() == 1:
				return 1
	else:
		if getoui() == 1:
			return 1
	ouiarray = []
	ouifile = open("oui.txt", 'r') # Open the file for reading.
	ouifile.seek(0)
	while (True):
		line = ouifile.readline() # Read each line until the end of file.
		if not line:
			break
		if line == "\n": # Ignore newlines.
			continue
		else:
			# Split the line by tabs and spaces and select the first part of the line.
			line = line.split('\t')
			line = line[0].split(' ')
			line = line[0]
			# Use Regex matching to determine it is the format of a MAC address.
			pattern = re.compile("[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}")
			if pattern.match(line):
				ouiarray.append(line.replace('-',':')) # Replace the hyphens with colons.
	return ouiarray

def connect_cowrie(host, prt, usr, psw):
	global score
	try:
		print("Connecting to {0} with username \"{1}\" and password \"{2}\"".format(host, usr, psw))
		s = ShellHandler(host, prt, usr, psw)
		print("Executing commands...")
		# ifconfig
		ouiarray = generate_oui()
		ouiexists = False
		(stdin, stdout, stderr) = s.execute("ifconfig")
		for line in stdout:
			if "HWaddr" in line:
				for oui in ouiarray:
					if re.search(oui, line):
						ouiexists = True
						break
				break
		if ouiexists == False:
			print("[+8] ifconfig shows an invalid MAC address!")
			score += 8
		# version
		versioncheck = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1"
		(stdin, stdout, stderr) = s.execute("cat /proc/version")
		for line in stdout:
			if versioncheck in line:
				print("[+4] Same OS found in version file!")
				score += 4
				break
		# uname
		unamecheck = "3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
		(stdin, stdout, stderr) = s.execute("uname -a")
		for line in stdout:
			if unamecheck in line:
				print("[+4] uname command shows same version!")
				score += 4
				break
		# meminfo
		memcheck = "MemTotal:        4054744 kB"
		(stdin, stdout, stderr) = s.execute("cat /proc/meminfo")
		for line in stdout:
			if re.search(memcheck, line):
				print("[+4] Similar memory information!")
				score += 4
				break
		# mounts
		mountscheck = """rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,relatime 0 0
udev /dev devtmpfs rw,relatime,size=10240k,nr_inodes=997843,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,relatime,size=1613336k,mode=755 0 0
/dev/dm-0 / ext3 rw,relatime,errors=remount-ro,data=ordered 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
/dev/sda1 /boot ext2 rw,relatime 0 0
/dev/mapper/home /home ext3 rw,relatime,data=ordered 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw,relatime 0 0"""
		(stdin, stdout, stderr) = s.execute("cat /proc/mounts")
		lines = ""
		for line in stdout:
			lines += line
		if re.search(mountscheck, lines):
			print("[+4] Exact match with mounts!")
			score += 4
		# cpuinfo
		cpucheck = "Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz"
		(stdin, stdout, stderr) = s.execute("cat /proc/cpuinfo")
		for line in stdout:
			if cpucheck in line:
				print("[+8] Same CPU Information found!")
				score += 8
				break
		# group
		(stdin, stdout, stderr) = s.execute("cat /etc/group")
		for line in stdout:
			if "phil" in line:
				print("[+16] User \"phil\" exists in group file!")
				score += 16
				break
		# passwd
		(stdin, stdout, stderr) = s.execute("cat /etc/passwd")
		for line in stdout:
			if "phil" in line:
				print("[+16] User \"phil\" exists in passwd file!")
				score += 16
				break
		# shadow
		(stdin, stdout, stderr) = s.execute("cat /etc/shadow")
		for line in stdout:
			if "phil" in line:
				print("[+16] User \"phil\" exists in shadow file!")
				score += 16
				break
		# hosts
		(stdin, stdout, stderr) = s.execute("cat /etc/hosts")
		for line in stdout:
			if "nas3" in line:
				print("[+8] Common host \"nas3\" exists in hosts file!")
				score += 8
				break
		# hostname
		(stdin, stdout, stderr) = s.execute("cat /etc/hostname")
		for line in stdout:
			if "svr04" in line:
				print("[+8] Common hostname \"svr04\" exists!")
				score += 8
				break
		# issue
		issuecheck = "Debian GNU/Linux 7 \\n \\l"
		(stdin, stdout, stderr) = s.execute("cat /etc/issue")
		for line in stdout:
			if issuecheck in line:
				print("[+4] Common OS issue exists!")
				score += 4
				break
		del s
	except paramiko.ssh_exception.NoValidConnectionsError:
		print("\033[1;33;49mError: Could not connect to host!\033[0;37;49m")
		sys.exit()
	except paramiko.ssh_exception.AuthenticationException:
		print("\033[1;33;49mError: Could not authenticate, incorrect username/password.\033[0;37;49m")
		sys.exit()
	except paramiko.ssh_exception.SSHException:
		print("\033[1;33;49mError: SSH connection error!\033[0;37;49m")
		sys.exit()

def evaluation():
	print("Total Cowrie Score: " + str(score) + "%")
	if score == 100:
		print("Verdict: \033[1;31;49mA completely default Cowrie honeypot\033[0;37;49m")
	elif score > 90:
		print("Verdict: \033[1;31;49mA Cowrie honeypot with slightly changed values\033[0;37;49m")
	elif score > 75:
		print("Verdict: \033[1;31;49mA Cowrie honeypot with some changed values\033[0;37;49m")
	elif score > 50:
		print("Verdict: \033[1;33;49mMost likely a Cowrie honeypot\033[0;37;49m")
	elif score > 25:
		print("Verdict: \033[1;33;49mPossibly a Cowrie honeypot\033[0;37;49m")
	elif score > 0 :
		print("Verdict: \033[1;32;49mSeems to be a real system\033[0;37;49m")
	elif score == 0:
		print("Verdict: \033[1;34;49mIf this was a honeypot, I'd be fooled\033[0;37;49m")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(usage='{0} <host> [options]'.format(sys.argv[0]))
	parser.add_argument("host", action='store', help="Host to connect to.")
	parser.add_argument("-u", "--username", action='store', default=USER, help="Connect using a specific username. Default is {0}.".format(USER))
	parser.add_argument("-p", "--password", action='store', default=PASSWORD, help="Connect using a specific password. Default is \"{0}\".".format(PASSWORD))
	parser.add_argument("--port", action='store', default=PORT, help="Connect using a specific port. Default is \"{0}\".".format(PORT))
	args = parser.parse_args()
	lenargs = len(vars(args))

	# if lenargs < 3:
	# 	parser.print_help()
	# 	sys.exit()
	connect_cowrie(args.host, args.port, args.username, args.password)
	evaluation()