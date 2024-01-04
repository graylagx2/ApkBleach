#!/bin/bash

echo -e "Checking if the script is running as root!"

# Check if script is running as root user
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use 'sudo' or run as root."
    exit 1
fi

echo -e "\nUpdating your system, please wait\n"
sleep 1

# Update system
apt update

echo -e "\nInstalling required dependencies, please wait!\n"
sleep 1

# Install pip
apt install python3-pip -y

# Install Python if not already installed
apt install python3 -y

# Install virtualenv
pip3 install virtualenv

# Create and activate a virtual environment
python3 -m virtualenv venv
source venv/bin/activate

# Install required Python packages
pip install setuptools argparse colorama Pillow pkg_resources requests pyfiglet

# Install system packages
apt install libjpeg-dev -y

# Install Python packages from system repositories
pip install pillow pkg_resources pyfiglet

# Install pyfiglet dependencies
apt install fonts-ubuntu -y

# Deactivate virtual environment
deactivate

echo -e "\nDone, run the 'setup.py' file now!\n"
sleep 2