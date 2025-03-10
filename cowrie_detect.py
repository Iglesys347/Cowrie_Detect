#!/usr/bin/python3

import paramiko
import sys
import argparse
import re
from socket import gaierror
from OuiLookup import OuiLookup
import nmap3

USER = "root"
PASSWORD = ""
score = 0
maxscore = 0
PORT = 22

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
            line = re.compile(
                r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).replace('\b', '').replace('\r', '')
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

# The following function below parses a sanitized oui.txt file and returns an array of valid OUIs from https://linuxnet.ca
# The array will be reffered in the ifconfigarp() function


# def getoui():
#     print("Retrieving a sanitized OUI file from \"https://standards-oui.ieee.org/\".")
#     print("This may take a minute.")
#     try:
#         urllib.request.urlretrieve(
#             "https://standards-oui.ieee.org/", filename="oui.txt")
#         return 0
#     except Exception:
#         return 1

# # Firstly, the function below checks if the oui.txt file is in the same directory as the script.
# # If the file exists then it will prompt the user to test the file or retrieve a new one.
# # The function then proceeds to open the file in read mode and using the regex to determine the format of a MAC azddress.
# # If the oui.txt file doesnt exist then it will use the getoui() function to retrieve a new one.


# def generate_oui():
#     if os.path.isfile("oui.txt"):
#         parsebool = ""
#         print("An oui file has been found. Use this file to test or retrieve a new one?")
#         while parsebool != 'p' and parsebool != 'r':
#             parsebool = input("Input (p/r):")
#             parsebool.lower()
#         if parsebool == 'r':
#             if getoui() == 1:
#                 return 1
#     else:
#         if getoui() == 1:
#             return 1
#     ouiarray = []
#     ouifile = open("oui.txt", 'r')  # Open the file for reading.
#     ouifile.seek(0)
#     while (True):
#         line = ouifile.readline()  # Read each line until the end of file.
#         if not line:
#             break
#         if line == "\n":  # Ignore newlines.
#             continue
#         else:
#             # Split the line by tabs and spaces and select the first part of the line.
#             line = line.split('\t')
#             line = line[0].split(' ')
#             line = line[0]
#             # Use Regex matching to determine it is the format of a MAC address.
#             pattern = re.compile(
#                 "[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}\-[0-9A-Fa-f]{2}")
#             if pattern.match(line):
#                 # Replace the hyphens with colons.
#                 ouiarray.append(line.replace('-', ':'))
#     return ouiarray

# The following function uses a python package with nmap to scan for the SSH and OS version.
# The OS detection checks if the string is similar to the default installation and if so then the honeypot score is incremented


def nmaptest(host, increment):
    global maxscore
    score = 0
    try:
        scanner = nmap3.Nmap()
        print("Running Nmap Scan...")
        results = scanner.nmap_version_detection(host)
        for line in results['127.0.0.1']['ports']:
            if "6.0p1 Debian 4+deb7u2" in line["service"]["version"]:
                print(
                    "[\033[1;33;49m+{0}\u001b[0m] Nmap shows same OS version!".format(increment))
                maxscore += increment
                score += increment
                break
        if score == 0:
            print(
                "[\033[1;32;49mOK\u001b[0m] Nmap shows different OS version to default.")
    except Exception:
        print("[\033[1;31;49m!!\u001b[0m] Nmap could not scan host. \033[0;33;49mIs nmap installed?\u001b[0m")

    return score

# The function below reads all MAC addresses returned by the executed command and checks whether they are valid
# A score is generated based on the total number of MAC addesses and number of invalid addresses
# Regex matching is used  to find the MAC addresses with the OUI array being created from the getoui() and generate_oui() functions.
# If the two aforementioned functions return a code of 1, the ifconfigarp() function is skipped.
# By default, the arp file does not exist on a fresh installation of Cowrie which the script also checks for and increses the score if it doesnt exists.
# Lasltly, if the getoui() and generate_oui() does not return a single MAC address each then the score is also incremented.


def ifconfigarp(s, increment):
    global maxscore
    score = 0
    #ouiarray = generate_oui()
    if True:  # type(ouiarray) == list:
        ifconfigscore = 0
        (stdin, stdout, stderr) = s.execute("ifconfig")
        pattern = "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
        macs = (re.findall(pattern, str(stdout)))
        if len(macs) > 0:
            maxscore += increment * len(macs)
            maxifconfigscore = increment * len(macs)
            for m in macs:
                # ouiexists = False
                # for oui in ouiarray:
                #     if oui in m.upper()[:8]:
                #         ouiexists = True
                #         break
                # if ouiexists == False:
                #     ifconfigscore += maxifconfigscore / len(macs)
                if None in OuiLookup().query(m)[0].values():
                    ifconfigscore += maxifconfigscore / len(macs)

            if ifconfigscore > 0:
                print("[\033[1;33;49m+{0}/{1}\u001b[0m] ifconfig shows OUI(s) not in the OUI list.".format(
                    ifconfigscore, maxifconfigscore))
                score += ifconfigscore
            elif ifconfigscore == 0:
                print(
                    "[\033[1;32;49mOK\u001b[0m] ifconfig shows valid MAC address(s).")
        else:
            score += increment
            maxscore += increment
            print(
                "[\033[1;33;49m+{0}\u001b[0m] ifconfig does not show any MAC addresses.".format(ifconfigscore))
        (stdin, stdout, stderr) = s.execute("cat /proc/net/arp")
        arpscore = 0
        if re.search("No such file or directory", str(stdout)):
            print(
                "[\033[1;33;49m+{0}\u001b[0m] arp file does not exist!".format(increment))
            score += increment
            maxscore += increment
            return score
        pattern = "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
        macs = (re.findall(pattern, str(stdout)))
        if len(macs) > 0:
            #maxscore += increment * len(macs)
            maxarpscore = increment * len(macs)
            for m in macs:
                # ouiexists = False
                # for oui in ouiarray:
                #     if oui in m.upper()[:8]:
                #         ouiexists = True
                #         break
                # if ouiexists == False:
                #     arpscore += maxarpscore / len(macs)
                if None in OuiLookup().query(m)[0].values():
                    arpscore += maxarpscore / len(macs)
            if arpscore > 0:
                print(
                    "[\033[1;33;49m+{0}/{1}\u001b[0m] arp file shows OUI(s) not in the OUI list.".format(arpscore, maxarpscore))
                score += arpscore
            elif arpscore == 0:
                print(
                    "[\033[1;32;49mOK\u001b[0m] arp file shows valid MAC address(s).")
        else:
            score += increment
            maxscore += increment
            print(
                "[\033[1;33;49m+{0}\u001b[0m] arp file does not show any MAC addresses.".format(arpscore))
    else:
        print("[\033[1;31;49m!!\u001b[0m] Could not retrieve the OUI file. Skipping MAC address testing.")

    return score

# The following function checks for the version name by reading the version file in the /proc directory
# If a string matches in the file, the score is incremented


def version(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    # Function searches for this script
    versioncheck = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1"
    (stdin, stdout, stderr) = s.execute("cat /proc/version")
    for line in stdout:
        if versioncheck in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Same OS found in version file!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] OS does not match with default.")

    return score

# The function below uses the "uname-a" command to search and match the two strings with the results.
# For each string check, the score is incremented for strings matched


def uname(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    unamescore = 0
    unamecheck = "3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
    (stdin, stdout, stderr) = s.execute("uname -a")
    for line in stdout:
        if unamecheck in line:
            unamescore += increment
            break
        if re.search("3.2.0-4-amd64", line):
            unamescore += increment / 2
        if "#1 SMP Debian 3.2.68-1+deb7u1" in line:
            unamescore += increment / 2
    if unamescore > 0:
        print(
            "[\033[1;33;49m+{0}\u001b[0m] uname command shows similar version!".format(str(unamescore)))
        score += unamescore
    else:
        print(
            "[\033[1;32;49mOK\u001b[0m] uname command does not similar version to default.")

    return score

# The following function uses the cat command to read the meminfo file in the directory proc/ of the honeyfs
# The following checks the first line (memcheck) of meminfo for matches. If the strings match then the score is incremented.


def meminfo(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    memcheck = "MemTotal:        4054744 kB"
    (stdin, stdout, stderr) = s.execute("cat /proc/meminfo")
    for line in stdout:
        if re.search(memcheck, line):
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Similar memory information!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] Memory information is not similar.")

    return score

# The following function below simply checks if the strings identified under 'mountscheck' are similar to the mounts file in the proc directory of honeyfs.
# For each string checked, the score is incremented


def mounts(s, increment):
    global maxscore
    maxscore += increment
    score = 0
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
        print(
            "[\033[1;33;49m+{0}\u001b[0m] Exact match with mounts!".format(increment))
        score += increment
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] Mounts is different to default.")

    return score

# The following function checks if the strings identified under 'cpucheck' match with the cpuinfo file in the proc directory of the honeyfs.
# If the strings match, the score is incremented


def cpuinfo(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    cpucheck = "Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz"
    (stdin, stdout, stderr) = s.execute("cat /proc/cpuinfo")
    for line in stdout:
        if cpucheck in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Same CPU found in cpuinfo file!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] CPU name is different to default.")

    return score

# The function below checks if the values "phil" exists in the group file under the directory /etc of the honeyfs
# For each line of string that matches, the score is incremented


def group(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    (stdin, stdout, stderr) = s.execute("cat /etc/group")
    for line in stdout:
        if "phil" in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] User \"phil\" exists in group file!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] User \"phil\" not found in group file.")

    return score

# Similar to the group() function, the following below checks if the "phil" value exists in the passwd file under the directory /etc of the honeyfs
# For each line of string that matches, the score is incremented


def passwd(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    (stdin, stdout, stderr) = s.execute("cat /etc/passwd")
    for line in stdout:
        if "phil" in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] User \"phil\" exists in passwd file!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] User \"phil\" not found in passwd file.")

    return score

# Similar to the group() and passwd() functions, the following function below checks if the values "phil" exists in the shadow file under the directory /etc of the honeyfs
# For each line of string that matches, the score is incremented.


def shadow(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    (stdin, stdout, stderr) = s.execute("cat /etc/shadow")
    for line in stdout:
        if "phil" in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] User \"phil\" exists in shadow file!".format(increment))
            score += increment
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] User \"phil\" not found in shadow file.")

    return score

# The following function checks if the value "nas3" exists in the hosts file of the directory /etc in the honeyfs
# If there is a string match, then the score is incremented


def hosts(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    (stdin, stdout, stderr) = s.execute("cat /etc/hosts")
    for line in stdout:
        if "nas3" in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Common host \"nas3\" exists in hosts file!".format(increment))
            score += increment
            break
    if score == 0:
        print(
            "[\033[1;32;49mOK\u001b[0m] Common host \"nas3\" does not exist in hosts file.")

    return score

# The function below checks for strings that have "svr04" in the hostname file of the directory /etc inside honeyfs
# If there is a string match in the hostname file or the terminal, then the score gets incremented


def hostname(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    (stdin, stdout, stderr) = s.execute("cat /etc/hostname")
    for line in stdout:
        if "svr04" in line:
            score += increment / 2
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Common hostname \"svr04\" exists in hostname file!".format(str(increment / 2)))
            break
    if score == 0:
        print("[\033[1;32;49mOK\u001b[0m] Hostname is not \"svr04\" in hostname file.")
    (stdin, stdout, stderr) = s.execute("hostname")
    for line in stdout:
        if "svr04" in line:
            score += increment / 2
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Common hostname \"svr04\" exists in terminal!".format(str(increment / 2)))
            break
    if score == increment / 2:
        print(
            "[\033[1;32;49mOK\u001b[0m] Hostname in terminal is different to \"svr04\".")

    return score

# The following function below checks if the string identified under "issuecheck" matches with the issue file in the directoryt /etc of the honeyfs
# If there is a string match, then it increments the score. Otherwise it will print a message that the OS issue is different to a dafault issue file of a honeypot.


def issue(s, increment):
    global maxscore
    maxscore += increment
    score = 0
    issuecheck = "Debian GNU/Linux 7 \\n \\l"
    (stdin, stdout, stderr) = s.execute("cat /etc/issue")
    for line in stdout:
        if issuecheck in line:
            print(
                "[\033[1;33;49m+{0}\u001b[0m] Common OS issue exists in issue file!".format(increment))
            score += increment
            break
    if score == 0:
        print(
            "[\033[1;32;49mOK\u001b[0m] OS Issue is different to default in issue file.")

    return score

# The following function below will attempt to connect to the host with a new SSH client object which then calls to all functions describes previously to execute.
# The exception handlers check for the following errors:
    # failed authentication
    # hostname couldnot be resolved
    # generic error caused by paramiko


def connect_cowrie(host, prt, usr, psw):
    global score
    try:
        print("Connecting to {0} with username \"{1}\" and password \"{2}\"".format(
            host, usr, psw))
        s = ShellHandler(host, prt, usr, psw)
        print("Connected!")
        print("Executing commands..")
        score += nmaptest(host, 10)
        score += ifconfigarp(s, 10)
        score += version(s, 5)
        score += uname(s, 5)
        score += meminfo(s, 5)
        score += mounts(s, 5)
        score += cpuinfo(s, 10)
        score += group(s, 20)
        score += passwd(s, 20)
        score += shadow(s, 20)
        score += hosts(s, 5)
        score += hostname(s, 10)
        score += issue(s, 5)
        del s
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("\033[1;33;49mError: Could not connect to host!\u001b[0m")
        sys.exit()
    except paramiko.ssh_exception.AuthenticationException:
        print(
            "\033[1;33;49mError: Could not authenticate, incorrect username/password.\u001b[0m")
        sys.exit()
    except paramiko.ssh_exception.SSHException:
        print("\033[1;33;49mError: SSH connection error!\u001b[0m")
        sys.exit()
    except gaierror:
        print(
            "\033[1;33;49mError: Host not known! Try using a valid IP address.\u001b[0m")
        sys.exit()
    except Exception as e:
        print("\033[1;31;49mError: Fatal error occurred!\u001b[0m")
        print("\033[1;31;49m" + e + "\u001b[0m")
        sys.exit()

# The function below evaluates an overall percentage of the scores outputed by the connect_cowrie() function


def evaluation():
    global score
    global maxscore
    percentage = score / maxscore * 100
    percentage = round(percentage, 2)
    print()
    print("Total Score: {0} / {1} ({2}%)".format(score,
          maxscore, str(percentage)))
    if percentage == 100:
        print(
            "Verdict: \033[1;31;49mPerfect score! A completely default Cowrie honeypot!\u001b[0m")
    elif percentage > 90:
        print(
            "Verdict: \033[1;31;49mA Cowrie honeypot with slightly changed values.\u001b[0m")
    elif percentage > 75:
        print("Verdict: \033[1;31;49mA modified Cowrie honeypot.\u001b[0m")
    elif percentage > 50:
        print(
            "Verdict: \033[1;31;49mAn almost disguised Cowrie honeypot.\u001b[0m")
    elif percentage > 25:
        print(
            "Verdict: \033[1;33;49mCould be Cowrie honeypot or real system.\u001b[0m")
    elif percentage > 0:
        print("Verdict: \033[1;32;49mReal system.\u001b[0m")
    elif percentage == 0:
        print(
            "Verdict: \033[1;34;49mZero score! If this was a honeypot, I'd be fooled!\u001b[0m")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage='{0} <host> [options]'.format(sys.argv[0]))
    parser.add_argument("host", action='store', help="Host to connect to.")
    parser.add_argument("-u", "--username", action='store', default=USER,
                        help="Connect using a specific username. Default is {0}.".format(USER))
    parser.add_argument("-p", "--password", action='store', default=PASSWORD,
                        help="Connect using a specific password. Default is \"{0}\".".format(PASSWORD))
    parser.add_argument("--port", action='store', default=PORT,
                        help="Connect using a specific port. Default is \"{0}\".".format(PORT))
    args = parser.parse_args()
    lenargs = len(vars(args))

    connect_cowrie(args.host, args.port, args.username, args.password)
    evaluation()
