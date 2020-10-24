"""
Python Version 3.8

Singapore Institute of Technology (SIT)
Information and Communications Technology (Information Security), BEng (Hons)

ICT-2203 Network Security Assignment 1

Author: @ 
	Tan Zhao Yea / 1802992
	Chin Clement / 1802951
	Gerald Peh Wei Xiang / 1802959
Academic Year: 2020/2021
Lecturer: Woo Wing Keong
Submission Date: 25th October 2020

This script holds the code to perform various attacks in our Assignment. 
 	- Telnet Bruteforce, DHCP Staravation, Rogue DHCP Server, DNS Poisoning
"""

import os
import subprocess
import cowsay

from pyfiglet import Figlet, figlet_format

# Log File Configurations
DHCP_STARVE_LOG = os.path.abspath("logs/dhcp_starve.txt")
DNS_POISON_LOG = os.path.abspath("logs/dns_poison.txt")


# Error Message Dictionary
ERRMSG = {
    1: "Value Error! The option input is not provided in the function"
}

# Rogue DHCP Abs Path
META_DHCP_SERVER_DIR = os.path.abspath("scripts/meta_dhcp_setup.rc")

# Function to display the main menu
def display_ui():
	""" Display the Banner Message """
	print(figlet_format("Welcome To ICT-2203-F17 Attack Script"))
	cowsay.cow("Do anything you want, just don't get caught :)")
	cowsay.cow("Moooo")


def options_ui():
	""" Diplay the Options """
	print("")
	print("-=-=-=-=-=-=-=-=-=-=-= OPTIONS -=-=-=-=-=-=-=-=-=-=-=-=")
	print("1. Host Discovery.")
	print("2. Telnet Bruteforce Attack.")
	print("3. DHCP Starvation Attack.")
	print("4. Run Rogue DHCP Server.")
	print("5. DNS Poisoning.")
	print("6. Exit.")
	print("0. Clear Screen (Enter 0 to clear screen)")
	print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")


def exit_ui():
	"""Exit UI """
	cowsay.cow("Goodbye, Mooo, Mooo, Mooo :)")


def main():
	""" Main Function """
	display_ui()

	# Infinite Loop
	while True:
		try:			
			options_ui()
			print("[*] Which attack would you like to perform?")
			choice = int(input("[>]: "))

		except ValueError:
			print(ERRMSG.get(1))
			continue
		
		except KeyboardInterrupt:
			exit_ui()
			break

		else:
			if choice < 0 or choice > 6:
				print(ERRMSG.get(1))
				continue

		# Clear the Screen
		if choice == 0:
			os.system("clear")

		# Host Discovery 
		elif choice == 1:
			print("\t[+] Enter Network IP Address/Subnet")
			network_cidr = input("\t[>]: ")

			print("\n[*] Running Host Discovery")

			subprocess.run(["python3","scripts/host_discovery.py",network_cidr])


		# Telnet Bruteforce Attack
		elif choice == 2:
			print("\t[+] Enter Target IP Address")
			target_ip = input("\t[>]: ")
			print("\t[+] Enter Dictionary File")
			password_file = input("\t[>]:")

			print("\n[*] Running Telnet Bruteforce Attack")
			
			try:
				subprocess.run(["python3","scripts/telnet_bruteforce.py",target_ip,password_file])
			except EOFError:
				print("[ERR] Telnet Connection Closed")
			
			input("Press Enter to return to main menu...")
			continue

		
		# DHCP Starvation Attack
		elif choice == 3:
			print("\n[*] Running DHCP Starvation Attack")
			
			subprocess.Popen(["python3","scripts/dhcp_starvation.py"], close_fds=True)
			print(f"[*] Please refer to {DHCP_STARVE_LOG} for runtime information ...")
			
			input("Press Enter to return to main menu...")
			continue

		
		# Rogue DHCP Server
		elif choice == 4:
			print("\n[*] Setting up Rogue DHCP Server")
			
			print("\n[*] Please open a new terminal and run the following commands:")
			print(f"\t[+] sudo msfconsole -q -r '{META_DHCP_SERVER_DIR}'")

			input("Press Enter to return to main menu...")
			continue


		# DNS Attack
		elif choice == 5:
			print("\n[*] Running DNS Poisoning Attack")			
			
			subprocess.Popen(["python3","scripts/dns_poison.py"], close_fds=True)
			print(f"[*] Please refer to {DNS_POISON_LOG} for runtime information ...")

			input("Press Enter to return to main menu...")
			continue

		# Exit Program
		elif choice == 6:
			exit_ui()
			break


if __name__ == '__main__':
	# Make log directory folder if it does not exist
	if not os.path.exists('logs/'):
		os.makedirs('logs/')

	main()