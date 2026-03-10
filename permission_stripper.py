
#necessary imports
import win32job
import win32api
import win32con
import win32security
import psutil
import time
import ntsecuritycon

# --- Configuration for Vice City Multiplayer (VCMP) ---
TARGET_PROCESSES = ["gta-vc.exe", "VCMPBrowser.exe"]
MONITOR_INTERVAL = 0.5  # Check every 500ms for new processes

def harden_process_security(pid, name):
    """
    Applies the most restrictive DACL possible to the process.
    Marks the DACL as PROTECTED to prevent inheritance/override.
    """
    try:
        hProcess = win32api.OpenProcess(win32con.WRITE_DAC | win32con.READ_CONTROL, False, pid)
        dacl = win32security.ACL()
        
        # SIDs for target groups
        everyone_sid = win32security.LookupAccountName(None, "Everyone")[0]
        admin_sid = win32security.LookupAccountName(None, "Administrators")[0]
        system_sid = win32security.LookupAccountName(None, "SYSTEM")[0]

        # Deny ALL access to Everyone, Administrators, and SYSTEM
        full_access = win32con.PROCESS_ALL_ACCESS | win32con.ACCESS_SYSTEM_SECURITY
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, full_access, everyone_sid)
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, full_access, admin_sid)
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, full_access, system_sid)

        win32security.SetSecurityInfo(
            hProcess, win32security.SE_KERNEL_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
        win32api.CloseHandle(hProcess)
        print(f"[SUCCESS] Hardened DACL applied to {name} ({pid}).")
        return True
    except Exception as e:
        print(f"[!] DACL Hardening failed for {name}: {e}")
        return False

def create_restricted_job_object():
    """
    Creates a Windows Job Object to sandbox the processes.
    Restricts UI interaction, clipboard access, and child process breakaway.
    """
    hJob = win32job.CreateJobObject(None, "VCMP_Security_Sandbox")
    
    # Initialize complete dictionary for compatibility
    basic_limits = {
        'PerProcessUserTimeLimit': 0, 'PerJobUserTimeLimit': 0,
        'LimitFlags': win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | \
                      win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
        'MinimumWorkingSetSize': 0, 'MaximumWorkingSetSize': 0, 
        'ActiveProcessLimit': 0, 'Affinity': 0, 'PriorityClass': 0, 'SchedulingClass': 0,
    }
    
    extended_info = {
        'BasicLimitInformation': basic_limits,
        'IoInfo': {
            'ReadOperationCount': 0, 'WriteOperationCount': 0, 'OtherOperationCount': 0,
            'ReadTransferCount': 0, 'WriteTransferCount': 0, 'OtherTransferCount': 0
        },
        'ProcessMemoryLimit': 0, 'JobMemoryLimit': 0, 
        'PeakProcessMemoryUsed': 0, 'PeakJobMemoryUsed': 0,
    }
    win32job.SetInformationJobObject(hJob, win32job.JobObjectExtendedLimitInformation, extended_info)

    # UI Restrictions: Prevent access to clipboard, desktop, and global atoms
    ui_restrictions = {
        'UIRestrictionsClass': win32job.JOB_OBJECT_UILIMIT_GLOBALATOMS | \
                               win32job.JOB_OBJECT_UILIMIT_HANDLES | \
                               win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD | \
                               win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD | \
                               win32job.JOB_OBJECT_UILIMIT_DESKTOP | \
                               win32job.JOB_OBJECT_UILIMIT_EXITWINDOWS
    }
    win32job.SetInformationJobObject(hJob, win32job.JobObjectBasicUIRestrictions, ui_restrictions)
    
    print(f"[+] Security Sandbox Created: {hJob}")
    return hJob

def assign_process_to_job(hJob, pid, name):
    """Assigns the target process to the restricted Job Object."""
    try:
        hProc = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, pid)
        win32job.AssignProcessToJobObject(hJob, hProc)
        win32api.CloseHandle(hProc)
        print(f"[SUCCESS] {name} ({pid}) locked in Job Sandbox.")
        return True
    except Exception as e:
        print(f"[!] Job Assignment failed for {name}: {e}")
        return False

if __name__ == "__main__":
    print("--- INTELLIGENT SECURITY: ULTIMATE STEALTH PROTECTION ---")
    try:
        job_handle = create_restricted_job_object()
        assigned_pids = set()
        print(f"[*] Actively monitoring for: {', '.join(TARGET_PROCESSES)}")
        print("[*] Ensure this script runs as ADMINISTRATOR for full protection.")
        
        while True:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    p_name = proc.info['name']
                    p_pid = proc.info['pid']
                    if p_name in TARGET_PROCESSES and p_pid not in assigned_pids:
                        print(f"\n[DETECTED] Target Found: {p_name} ({p_pid})")
                        
                        # Sandbox Isolation
                        assign_process_to_job(job_handle, p_pid, p_name)
                        
                        # Stealth Hardening
                        harden_process_security(p_pid, p_name)
                        
                        assigned_pids.add(p_pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Cleanup list of terminated processes
            active_pids = {p.pid for p in psutil.process_iter(['pid'])}
            assigned_pids &= active_pids
            time.sleep(MONITOR_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n[*] Protection stopped by user.")
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
    finally:
        if 'job_handle' in locals():
            win32api.CloseHandle(job_handle)
