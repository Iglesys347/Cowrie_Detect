#cowrie_detect.py

import paramiko, sys
ERROR = "Usage mode:\n python cowrie_detect.py'ip'"
CREDENTIALS = {"root":"123456", "root":"root", "richard":"fout", "richard":"richard"}
USERS = ["richard", "root"]
PASSWORDS = ["root", "123456", "richard", "fout"]
COUNT = 0
COWRIE_PROVE = "RX bytes:102191499830 (102.1 GB)  TX bytes:68687923025 (68.6 GB)"
HOSTNAME = ""
TEST_COWRIE = 0
TEST_DIONAEA = 0
LISTA = []

def entrypoint():

	try:

		if "--help" in sys.argv:
			print ERROR
			print "entre"
		#elif "--ssh" in sys.argv:
			#LISTA.append("cowrie")
			#print "HIIIII"
		#elif "-smb" in sys.argv:
			#TEST_DIONAEA = 1
		else:
			pass

		lon= len(sys.argv)
		#print lon

		HOSTNAME = sys.argv[lon-1]
		print "hostname:"+HOSTNAME
	except:
		print ERROR


def connect_cowrie():

    s = paramiko.SSHClient()
    s.load_system_host_keys()
    for user in USERS:
    	for pwd in PASSWORDS:

    	s.connect(HOSTNAME, 22, user, pwd)
    	command = "ifconfig"
    	(stdin, stdout, stderr) = s.exec_command(command)
    	for line in stdout.readlines():
    		if COWRIE_PROVE in line:
    			COUNT = COUNT +100
	        
	   	 	s.close()


def evaluation():
	if COUNT > 90:
		print "Cowrie detected in "+ HOSTNAME


if __name__ == "__main__":
	entrypoint()
	connect_cowrie
	print LISTA
	if "cowrie" in LISTA:
		print "HAA"
		connect_cowrie()
		evaluation()



