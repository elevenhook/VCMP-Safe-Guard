# VCMP-Safe-Guard
Advanced runtime security sandbox and process isolator for VCMP. Protects against malicious server-side RCE, directory scanning, and unauthorized data exfiltration using Windows Job Objects and DACL hardening.

# [DESCRIPTION]     
It provides a lightweight sandbox-like environment focused on process isolation and stealth protection
1. Locking processes in a Windows Job Object (UI & System isolation).
2. Stripping Process Access Rights (DACL Hardening) to block external inspection.
3. Neutralizing Administrative Privileges via Restricted Tokens.
   
# [PREREQUISITES]
- Windows OS (Windows 10/11 recommended)
- Python 3.8+ (https://www.python.org/downloads/)

# [INSTALLATION COMMANDS]
- Open PowerShell/CMD as Administrator and run:
  
pip install pywin32

pip install psutil

If you plan to build an executable
pip install pyinstaller

# [USAGE]
1. Open PowerShell/CMD as Administrator.
2. Navigate to the directory containing this script.
3. Run the command:
   python permission_stripper.py
5. Launch your game/browser. The script will detect and lock them instantly.

# [DISCLAIMER]
This tool is for security defense purposes. It does not modify game files 
on disk; it only restricts permissions in memory at runtime.
