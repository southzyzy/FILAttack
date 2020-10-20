import os
import subprocess
import cowsay

from pyfiglet import Figlet, figlet_format

# Log File Configurations
DHCP_STARVE_LOG = "logs/dhcp_starve.txt"
DNS_POISON_LOG = "logs/dns_poison.txt"


ERRMSG = {
    1: "Value Error! The option input is not provided in the function"
}


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
	print("4. DNS Poisoning.")
	print("5. Exit.")
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
			if choice < 0 or choice > 5:
				print(ERRMSG.get(1))
				continue

		# Clear the Screen
		if choice == 0:
			os.system("clear")

		elif choice == 1:
			print("\t[+] Enter Network IP Address/Subnet")
			network_cidr = input("\t[>]: ")

			print("\n[*] Running Host Discovery")

			subprocess.run(["python3","host_discovery.py",network_cidr])


		# Telnet Bruteforce Attack
		elif choice == 2:
			print("\t[+] Enter Target IP Address")
			target_ip = input("\t[>]: ")
			print("\t[+] Enter Dictionary File")
			password_file = input("\t[>]:")

			print("\n[*] Running Telnet Bruteforce Attack")
			
			try:
				subprocess.run(["python3","telnet_bruteforce.py",target_ip,password_file])
			except EOFError:
				print("[ERR] Telnet Connection Closed")
			
			input("Press Enter to return to main menu...")
			continue

		
		# DHCP Starvation Attack
		elif choice == 3:
			print("\n[*] Running DHCP Starvation Attack")
			
			with open(DHCP_STARVE_LOG,"w") as in_file:
				subprocess.Popen(["python3","dhcp_starvation.py"], stdout=in_file, close_fds=True)
			
			print(f"[*] Please refer to {DHCP_STARVE_LOG} for runtime information ...")
			
			input("Press Enter to return to main menu...")
			continue

		
		# DNS Attack
		elif choice == 4:
			print("\n[*] Running DNS Poisoning Attack")
			with open(DNS_POISON_LOG,"w") as in_file:
				subprocess.Popen(["python3","dns_poison.py"], stdout=in_file, close_fds=True)
			print(f"[*] Please refer to {DNS_POISON_LOG} for runtime information ...")

			input("Press Enter to return to main menu...")
			continue

		# Exit Program
		elif choice == 5:
			exit_ui()
			break


if __name__ == '__main__':
	main()