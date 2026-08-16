import os
import shutil
import ctypes
from ctypes import wintypes
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# System Artifacts (Relative to root drive)
SYSTEM_ARTIFACTS = [
    # Core Metafiles & Streams
    r"$MFT",
    r"$LogFile",
    r"$Extend\$UsnJrnl:$J",
    r"$Extend\$ObjId",
    
    # System Hives & Execution Artifacts
    r"Windows\System32\winevt\Logs\*.evtx",
    r"Windows\Prefetch\*.pf",
    r"Windows\System32\config\SYSTEM",
    r"Windows\System32\config\SOFTWARE",
    r"Windows\System32\config\SAM",
    r"Windows\System32\config\SECURITY",
    r"Windows\System32\config\DEFAULT",
    r"Windows\System32\config\AMCACHE.hve",
    r"Windows\appcompat\Programs\Amcache.hve",
    r"Windows\System32\SRU\SRUDB.dat",
    r"Windows\inf\setupapi.dev.log",
    
    # Scheduled Tasks, Persistence & Network Config
    r"Windows\System32\Tasks\*",
    r"Windows\System32\drivers\etc\hosts",
    r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*",
    
    # System Folders, Crash Reports & Deletions
    r"$Recycle.Bin\*\*",
    r"ProgramData\Microsoft\Windows Defender\Support\*.log",
    r"ProgramData\Microsoft\Windows\WER\*",
]

USER_ARTIFACTS = [
    # Registry & Shell
    r"NTUSER.DAT",
    r"AppData\Local\Microsoft\Windows\UsrClass.dat",
    r"AppData\Roaming\Microsoft\Windows\Recent\*.lnk",
    r"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*",
    r"AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*",
    r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*",
    
    # Execution History, Crash Dumps & RDP Caches
    r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    r"AppData\Local\Microsoft\Terminal Server Client\Cache\*",
    r"AppData\Local\CrashDumps\*",
    
    # Browser Histories
    r"AppData\Local\Google\Chrome\User Data\Default\History",
    r"AppData\Local\Microsoft\Edge\User Data\Default\History",
]

# Win32 Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_BACKUP_NAME = "SeBackupPrivilege"
SE_RESTORE_NAME = "SeRestorePrivilege"

# Win32 CTypes Structures
class _U(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LARGE_INTEGER(ctypes.Union):
    _fields_ = [
        ("QuadPart", ctypes.c_longlong),
        ("u", _U)
    ]

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def enable_backup_privileges() -> bool:
    """Enables SeBackupPrivilege and SeRestorePrivilege on the process token."""
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        return False

    for privilege_name in [SE_BACKUP_NAME, SE_RESTORE_NAME]:
        luid = LUID()
        if advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)

    kernel32.CloseHandle(h_token)
    return True

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False

def elevate_privileges():
    if not is_admin():
        print("[!] Administrator rights required. Prompting for elevation...")
        
        script_path = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                f'"{script_path}" {params}', 
                None, 
                1
            )
            
            if ret > 32:
                print("[+] Elevated instance launched. Exiting parent process.")
                sys.exit(0)
            else:
                print(f"[-] Elevation declined or failed. Error code: {ret}")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Failed to request elevation: {e}")
            sys.exit(1)

def extract_ntfs_metafile_raw(target_drive: str, relative_metafile_path: str, dst_path: Path):
    """Generic raw volume reader for kernel-restricted NTFS metadata files and streams ($MFT, $LogFile, $UsnJrnl)."""
    kernel32 = ctypes.windll.kernel32

    clean_drive = target_drive.strip("\\/").strip(":")
    volume_path = f"\\\\.\\{clean_drive}:"

    handle = kernel32.CreateFileW(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    if handle == -1 or handle == 0:
        err = kernel32.GetLastError()
        raise PermissionError(f"Raw Volume Handle CreateFileW failed on '{volume_path}' with error code: {err}")

    dst_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Read NTFS Boot Sector (512 bytes)
        boot_sector = ctypes.create_string_buffer(512)
        bytes_read = wintypes.DWORD()
        
        if not kernel32.ReadFile(handle, boot_sector, 512, ctypes.byref(bytes_read), None):
            raise RuntimeError(f"Failed to read boot sector. Error code: {kernel32.GetLastError()}")

        raw_data = boot_sector.raw
        if raw_data[3:11] != b"NTFS    ":
            raise RuntimeError("Target volume is not formatted with NTFS.")

        bytes_per_sector = int.from_bytes(raw_data[11:13], "little")
        sectors_per_cluster = raw_data[13]
        cluster_size = bytes_per_sector * sectors_per_cluster
        
        # Calculate cluster offset based on target system file
        mft_lcn = int.from_bytes(raw_data[0x30:0x38], "little")
        
        if "$MFT" in relative_metafile_path:
            file_offset = mft_lcn * cluster_size
            max_bytes = 256 * 1024 * 1024  # Limit read to 256MB for MFT
        elif "$LogFile" in relative_metafile_path:
            file_offset = (mft_lcn * cluster_size) + (256 * 1024 * 1024)
            max_bytes = 64 * 1024 * 1024   # Limit read to 64MB
        else:
            # Fallthrough for alternate data streams ($UsnJrnl:$J)
            file_offset = mft_lcn * cluster_size
            max_bytes = 128 * 1024 * 1024

        li_offset = LARGE_INTEGER(file_offset)
        if not kernel32.SetFilePointerEx(handle, li_offset, None, 0):
            raise RuntimeError(f"Failed seeking to cluster offset. Error code: {kernel32.GetLastError()}")

        chunk_size = 1024 * 1024  # 1MB chunks
        bytes_extracted = 0
        buffer = ctypes.create_string_buffer(chunk_size)

        with open(dst_path, "wb") as dst_file:
            while bytes_extracted < max_bytes:
                success = kernel32.ReadFile(handle, buffer, chunk_size, ctypes.byref(bytes_read), None)
                if not success or bytes_read.value == 0:
                    break

                dst_file.write(buffer.raw[:bytes_read.value])
                bytes_extracted += bytes_read.value

                # Exit stream read if hitting unallocated cluster blocks
                if bytes_extracted >= (2 * 1024 * 1024) and buffer.raw[:4] == b"\x00\x00\x00\x00":
                    break

    finally:
        kernel32.CloseHandle(handle)

class VSSManager:
    """Context manager to create, mount, and clean up a VSS snapshot using PowerShell CIM."""
    def __init__(self, drive_letter: str):
        cleaned_drive = drive_letter.strip("\\/").strip(":")
        self.drive = cleaned_drive + ":\\"
        self.shadow_id = None
        self.shadow_path = None
        self.mount_point = None

    def __enter__(self):
        print(f"[*] Creating Volume Shadow Copy for volume {self.drive} ...")
        
        ps_cmd = f"(Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{self.drive}'; Context='ClientAccessible'}}).ShadowID"
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps_cmd}"'
        
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        shadow_id = result.stdout.strip()

        if not shadow_id or "Error" in result.stderr or "Exception" in result.stderr:
            raise RuntimeError(f"VSS creation failed.\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")

        self.shadow_id = shadow_id

        path_cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object {{ $_.ID -eq \'{self.shadow_id}\' }}).DeviceObject"'
        path_res = subprocess.run(path_cmd, capture_output=True, text=True, shell=True)
        device_path = path_res.stdout.strip()

        if not device_path:
            raise RuntimeError("Failed to retrieve VSS DeviceObject path.")

        self.shadow_path = device_path

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.mount_point = Path(os.environ.get("TEMP", "C:\\Temp")) / f"vss_mount_{timestamp}"

        link_cmd = f'cmd /c mklink /d "{self.mount_point}" "{self.shadow_path}\\"'
        link_res = subprocess.run(link_cmd, capture_output=True, text=True, shell=True)

        if link_res.returncode != 0:
            raise RuntimeError(f"Failed to link VSS snapshot: {link_res.stderr}")

        print(f"[+] VSS Snapshot created ({self.shadow_id})")
        print(f"[+] Mounted successfully at: {self.mount_point}\n")
        return self.mount_point

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("\n[*] Starting Cleanup Procedure...")

        if self.mount_point and self.mount_point.exists():
            subprocess.run(f'cmd /c rmdir "{self.mount_point}"', shell=True, capture_output=True)
            print("[+] Removed symbolic mount point.")

        if self.shadow_id:
            del_cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object {{ $_.ID -eq \'{self.shadow_id}\' }} | Remove-CimInstance"'
            subprocess.run(del_cmd, shell=True, capture_output=True)
            print(f"[+] Deleted VSS Snapshot ({self.shadow_id}).")

def collect_triage_image(target_drive: str, output_dir: str):
    out_dir = Path(output_dir).resolve()
    succeeded = []
    failed = []

    with VSSManager(target_drive) as vss_root:
        
        def copy_file(source_path: Path):
            """Copies file from VSS snapshot, routing kernel-restricted NTFS metafiles through the generic raw reader."""
            try:
                rel_path = source_path.relative_to(vss_root)
                # Clean invalid ADS file path characters for local file creation
                dest_rel_string = str(rel_path).replace(":$J", "_J")
                dest_path = out_dir / dest_rel_string

                dest_path.parent.mkdir(parents=True, exist_ok=True)

                # Route protected metafiles or stream paths through raw reader if standard copy fails
                if source_path.name.startswith("$") or ":$" in str(source_path):
                    try:
                        shutil.copy2(source_path, dest_path)
                    except (PermissionError, OSError):
                        extract_ntfs_metafile_raw(target_drive, str(rel_path), dest_path)
                else:
                    shutil.copy2(source_path, dest_path)
                
                succeeded.append((str(rel_path), str(dest_path)))
                print(f"[SUCCESS] {rel_path}")
            except Exception as e:
                failed.append((str(source_path), str(e)))
                print(f"[FAILED]  {source_path} -> {e}")

        print("--- Processing System Artifacts via VSS ---")
        for pattern in SYSTEM_ARTIFACTS:
            for source_file in vss_root.glob(pattern):
                if source_file.is_file():
                    copy_file(source_file)

        print("\n--- Processing User Profiles via VSS ---")
        users_dir = vss_root / "Users"
        if users_dir.exists():
            for user_folder in users_dir.iterdir():
                if user_folder.is_dir() and not user_folder.name.startswith("All Users"):
                    for pattern in USER_ARTIFACTS:
                        for source_file in user_folder.glob(pattern):
                            if source_file.is_file():
                                copy_file(source_file)

    print("\n" + "=" * 65)
    print("                      COLLECTION SUMMARY                         ")
    print("=" * 65)
    print(f"Total Successful Extractions: {len(succeeded)}")
    print(f"Total Failed Extractions:     {len(failed)}")
    print("=" * 65)

    if failed:
        print("\n[!] FAILED EXTRACTIONS DETAIL:")
        for src, error in failed:
            print(f"  - {src}\n    Reason: {error}")

if __name__ == "__main__":
    elevate_privileges()
    enable_backup_privileges()

    TARGET_DRIVE = "C"
    TIMESTAMP = datetime.now().strftime("%m-%d-%Y_%H_%M_%S")
    OUTPUT_DIRECTORY = f".\\Triage_Image_{TIMESTAMP}"

    collect_triage_image(TARGET_DRIVE, OUTPUT_DIRECTORY)