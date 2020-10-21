# Cowrie Detection
## Are you connected to a honeypot? Let's find out!

This script attempts to connect to an SSH host and test many commands and files to compare to a default Cowrie installation.
For everything it finds, a score is assigned. The maximum score is 100%.

## Score Grading

```
    0% - - - - - - - - - 50% - - - - - - - - - 100%
Real System        Most Likely Cowrie     Default Cowrie
```

## Requirements

* Python 3
* Paramiko python module

## Usage

```
./cowrie_detect.py <host> [options]

Required:
  host                        IP Address or domain of host to connect to

Options:
  -u, --username: USERNAME    Connect with a specific username
  -p, --password: PASSWORD    Connect with a specific password
      --port: PORT            Connect with a specific port
