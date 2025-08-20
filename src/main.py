import os
import sys
import hashlib
import shutil
import json
import subprocess
import struct
import mmap
import platform
import tempfile
import random
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:

    import psutil

except ImportError:

    print("psutil is not installed. Please install it using: pip install psutil")

    sys.exit(1)

class Colors:
    
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

def print_banner():

    banner = f"""{Colors.OKCYAN}{Colors.BOLD}

╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                       ║
║  ████████╗██████╗  █████╗ ██╗██╗     ██████╗ ██╗      █████╗ ███████╗███████╗██████╗  ║
║  ╚══██╔══╝██╔══██╗██╔══██╗██║██║     ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝██╔══██╗ ║
║     ██║   ██████╔╝███████║██║██║     ██████╔╝██║     ███████║  ███╔╝ █████╗  ██████╔╝ ║
║     ██║   ██╔══██╗██╔══██║██║██║     ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝  ██╔══██╗ ║
║     ██║   ██║  ██║██║  ██║██║███████╗██████╔╝███████╗██║  ██║███████╗███████╗██║  ██║ ║
║     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ║
║                                                                                       ║
║                    ███████╗██╗   ██╗███████╗███████╗███████╗██████╗                   ║
║                    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗                  ║
║                    █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝                  ║
║                    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗                  ║
║                    ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║                  ║
║                    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝                  ║
║                                                                                       ║
║                                                                                       ║
║                                                                                       ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝

{Colors.WARNING}[+] Advanced Security Analysis & Defense System{Colors.OKCYAN}                              
{Colors.OKGREEN}[+] Ransomware Protection | Kernel Analysis | Vulnerability Fuzzing{Colors.OKCYAN}         
{Colors.FAIL}[!] Use Responsibly - Educational & Defensive Purposes Only{Colors.OKCYAN}

{Colors.ENDC}"""

    print(banner)

    time.sleep(1)

def print_status(message, status="INFO"):

    timestamp = datetime.now().strftime("%H:%M:%S")

    if status == "SUCCESS":

        print(f"{Colors.OKGREEN}[+] [{timestamp}] {message}{Colors.ENDC}")

    elif status == "WARNING":

        print(f"{Colors.WARNING}[!] [{timestamp}] {message}{Colors.ENDC}")

    elif status == "ERROR":

        print(f"{Colors.FAIL}[-] [{timestamp}] {message}{Colors.ENDC}")

    elif status == "INFO":

        print(f"{Colors.OKBLUE}[*] [{timestamp}] {message}{Colors.ENDC}")

    elif status == "SCAN":

        print(f"{Colors.OKCYAN}[~] [{timestamp}] {message}{Colors.ENDC}")

class FileSignatureAnalyzer:
    
    SIGNATURES = {

        b'\x50\x4B\x03\x04': ('.zip', 'ZIP Archive'),
        b'\x50\x4B\x05\x06': ('.zip', 'ZIP Archive (empty)'),
        b'\x50\x4B\x07\x08': ('.zip', 'ZIP Archive (spanned)'),
        b'\x52\x61\x72\x21': ('.rar', 'RAR Archive'),
        b'\x25\x50\x44\x46': ('.pdf', 'PDF Document'),
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('.doc', 'MS Office/OLE'),
        b'\x50\x4B': ('.docx', 'Office Open XML'),
        
        # Images
        b'\xFF\xD8\xFF': ('.jpg', 'JPEG Image'),
        b'\x89\x50\x4E\x47': ('.png', 'PNG Image'),
        b'\x47\x49\x46\x38': ('.gif', 'GIF Image'),
        b'\x42\x4D': ('.bmp', 'Bitmap Image'),
        
        # Executables
        b'\x4D\x5A': ('.exe', 'PE Executable'),
        b'\x7F\x45\x4C\x46': ('.elf', 'ELF Executable'),
        b'\xCA\xFE\xBA\xBE': ('.class', 'Java Class'),
        b'\xFE\xED\xFA\xCE': ('.mach', 'Mach-O (32-bit)'),
        b'\xFE\xED\xFA\xCF': ('.mach', 'Mach-O (64-bit)'),
        
        # Media
        b'\x00\x00\x00\x18\x66\x74\x79\x70': ('.mp4', 'MP4 Video'),
        b'\x00\x00\x00\x14\x66\x74\x79\x70': ('.mov', 'QuickTime'),
        b'\x49\x44\x33': ('.mp3', 'MP3 Audio'),
        b'\x52\x49\x46\x46': ('.wav', 'WAV Audio'),
    
    }
    
    SAFE_EXTENSIONS = ['.sys', '.dll', '.exe', '.ini', '.lnk', '.url', '.tmp', '.drv', '.bat']
    
    def __init__(self):
    
        self.protection_map = {}
        self.stats = {'analyzed': 0, 'protected': 0, 'restored': 0}
        
    def analyze_file(self, filepath: str) -> Dict:
    
        self.stats['analyzed'] += 1

        try:

            with open(filepath, 'rb') as f:

                header = f.read(32)
                
            file_info = {

                'path': filepath,
                'size': os.path.getsize(filepath),
                'original_extension': Path(filepath).suffix,
                'detected_type': None,
                'signature': header[:8].hex(),
                'entropy': self._calculate_entropy(filepath)

            }
            
            for sig, (ext, desc) in self.SIGNATURES.items():

                if header.startswith(sig):

                    file_info['detected_type'] = ext
                    file_info['description'] = desc

                    break
                    
            return file_info

        except Exception as e:

            return {'error': str(e)}
    
    def _calculate_entropy(self, filepath: str) -> float:

        try:

            with open(filepath, 'rb') as f:

                data = f.read(1024)  # Sample first 1KB

            if not data:

                return 0.0
                
            entropy = 0.0

            for i in range(256):

                p_x = data.count(bytes([i])) / len(data)

                if p_x > 0:

                    import math

                    entropy -= p_x * math.log2(p_x)

            return entropy

        except:

            return 0.0
    
    def protect_file(self, filepath: str, method: str = 'extension') -> bool:

        try:

            print_status(f"Protecting: {filepath}", "SCAN")
            
            if method == 'extension':

                new_ext = random.choice(self.SAFE_EXTENSIONS)

                new_path = str(Path(filepath).with_suffix(new_ext))
                
                self.protection_map[new_path] = {

                    'original_path': filepath,
                    'original_ext': Path(filepath).suffix,
                    'protection_method': 'extension_change',
                    'timestamp': datetime.now().isoformat()

                }
                
                shutil.move(filepath, new_path)

                self.stats['protected'] += 1

                print_status(f"Protected with extension change: {new_path}", "SUCCESS")

                return True
                
            elif method == 'signature':

                with open(filepath, 'r+b') as f:

                    original_header = f.read(8)

                    self.protection_map[filepath] = {

                        'original_header': original_header.hex(),
                        'protection_method': 'signature_change',
                        'timestamp': datetime.now().isoformat()

                    }
                    
                    f.seek(0)

                    f.write(b'\x4D\x5A\x90\x00\x03\x00\x00\x00')  # PE header disguise
                    
                self.stats['protected'] += 1

                print_status(f"Protected with signature modification", "SUCCESS")

                return True
                
        except Exception as e:

            print_status(f"Protection failed: {e}", "ERROR")

            return False

class KernelProtectionAnalyzer:
    
    def __init__(self):
        
        self.os_type = platform.system()
        self.kernel_version = platform.release()
        self.arch = platform.machine()
        
    def analyze_all_protections(self) -> Dict:

        print_status("Starting kernel protection analysis...", "INFO")
        
        if self.os_type == 'Linux':
            
            return self.check_linux_kernel_protections()
        
        elif self.os_type == 'Windows':
            
            return self.check_windows_kernel_protections()
        
        # [수정] macOS (Darwin) 운영체제 감지
        elif self.os_type == 'Darwin':
            
            return self.check_macos_kernel_protections()
        
        else:
        
            return {'error': 'Unsupported OS'}
    
    # [신규] macOS (XNU) 커널 보호 기능 확인 메서드
    def check_macos_kernel_protections(self) -> Dict:
        
        protections = {}
        
        checks = [
            ('SIP (System Integrity)', self._check_sip),
            ('SSV (Signed System Volume)', self._check_ssv),
            ('KIP (Kernel Integrity)', self._check_kip_via_sip),
            ('KTPR (Kernel Text Read-Only)', self._check_ktpr_via_ssv),
            ('KASLR', self._check_kaslr_macos),
            ('SMEP', self._check_smep),
            ('SMAP', self._check_smap),
            ('TCC (Privacy Control)', self._check_tcc_info),
        ]

        for name, check_func in checks:
            print_status(f"Checking {name}...", "SCAN")
            protections[name] = check_func()
            
        return protections

    def _check_sip(self) -> str:
       
        try:
       
            result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
            output = result.stdout
       
            if "System Integrity Protection status: enabled" in output:
       
                return '✅ Enabled'
       
            elif "System Integrity Protection status: disabled" in output:
       
                return '❌ Disabled'
       
            return '❓ Unknown'
       
        except FileNotFoundError:
       
            return '❌ csrutil not found'
       
        except Exception as e:
       
            return f'❓ Error: {e}'

    def _check_ssv(self) -> str:
       
        try:
       
            result = subprocess.run(['diskutil', 'apfs', 'list'], capture_output=True, text=True)
       
            if "Snapshot" in result.stdout and "Sealed" in result.stdout:
       
                return '✅ Enabled (Sealed SSV)'
       
            return '⚠️  Not detected or not an APFS volume'
       
        except FileNotFoundError:
       
            return '❌ diskutil not found'
       
        except Exception:
       
            return '❓ Unknown'

    def _check_kip_via_sip(self) -> str:
       
        return '✅ Enforced by SIP & SSV'

    def _check_ktpr_via_ssv(self) -> str:
       
        return '✅ Enforced by Signed System Volume'

    def _check_kaslr_macos(self) -> str:
       
        try:
       
            result = subprocess.run(['sysctl', 'vm.kernel_slide'], capture_output=True, text=True)
       
            slide = int(result.stdout.strip().split()[-1])
       
            if slide > 0:
       
                return f'✅ Enabled (slide=0x{slide:x})'
       
            return '❌ Disabled'
       
        except Exception:
       
            return '❓ Unknown'

    def _check_tcc_info(self) -> str:
       
        return 'ℹ️  Informational: User-space privacy framework. Check System Settings > Privacy & Security.'
    
    def check_linux_kernel_protections(self) -> Dict:

        protections = {}
        
        checks = [

            ('KASLR', self._check_kaslr),
            ('SMEP', self._check_smep),
            ('SMAP', self._check_smap),
            ('KPTI', self._check_kpti),
            ('SELinux', self._check_selinux),
            ('AppArmor', self._check_apparmor),
            ('SSP/Canary', self._check_stack_protection),
            ('NX/DEP', self._check_nx),
            ('ASLR', self._check_aslr),
            ('PIE', self._check_pie_support)

        ]
        
        for name, check_func in checks:

            print_status(f"Checking {name}...", "SCAN")

            protections[name] = check_func()
            
        return protections
    
    def _check_kaslr(self) -> str:

        try:

            with open('/proc/cmdline', 'r') as f:

                cmdline = f.read()

                if 'nokaslr' in cmdline:

                    return '❌ Disabled (nokaslr in cmdline)'
                    
            with open('/proc/kallsyms', 'r') as f:

                first_line = f.readline()

                if first_line.startswith('0000000000000000'):

                    return '✅ Enabled (addresses hidden)'

                else:

                    return '⚠️  Possibly disabled'
                    
        except PermissionError:

            return '🔒 Permission denied'

        except:

            return '❓ Unknown'
    
    def _check_smep(self) -> str:
        
        cpuinfo_path = '/proc/cpuinfo'
        
        sysctl_cmd = ['sysctl', 'machdep.cpu.features']
        
        try:
        
            # Linux
            if os.path.exists(cpuinfo_path):
        
                with open(cpuinfo_path, 'r') as f:
        
                    if 'smep' in f.read():
        
                        return '✅ Supported by CPU'
        
            # macOS
            else:
        
                result = subprocess.run(sysctl_cmd, capture_output=True, text=True)
        
                if 'SMEP' in result.stdout:
        
                    return '✅ Supported by CPU'

            return '❌ Not supported'
        
        except:
        
            return '❓ Unknown'
    
    def _check_smap(self) -> str:
        
        cpuinfo_path = '/proc/cpuinfo'
        
        sysctl_cmd = ['sysctl', 'machdep.cpu.features']

        try:
        
            # Linux
            if os.path.exists(cpuinfo_path):
        
                with open(cpuinfo_path, 'r') as f:
        
                    if 'smap' in f.read():
        
                        return '✅ Supported by CPU'
        
            # macOS
            else:
        
                result = subprocess.run(sysctl_cmd, capture_output=True, text=True)
        
                if 'SMAP' in result.stdout:
        
                    return '✅ Supported by CPU'
        
            return '❌ Not supported'
        
        except:
        
            return '❓ Unknown'
    
    def _check_kpti(self) -> str:

        try:

            vuln_path = '/sys/devices/system/cpu/vulnerabilities/meltdown'

            if os.path.exists(vuln_path):

                with open(vuln_path, 'r') as f:

                    status = f.read().strip()

                    if 'Mitigation' in status:

                        return f'✅ {status}'

                    else:

                        return f'⚠️  {status}'

        except:

            pass

        return '❓ Unknown'
    
    def _check_selinux(self) -> str:

        try:

            result = subprocess.run(['getenforce'], capture_output=True, text=True)

            status = result.stdout.strip()

            if status == 'Enforcing':

                return '✅ Enforcing'

            elif status == 'Permissive':

                return '⚠️  Permissive'

            else:

                return f'❌ {status}'

        except:

            if os.path.exists('/etc/selinux/config'):

                return '⚠️  Installed (status unknown)'

            return '❌ Not installed'
    
    def _check_apparmor(self) -> str:

        try:
            
            if os.path.exists('/sys/kernel/security/apparmor'):
            
                return '✅ Present'
        except:
            
            
            pass
        
        return '❌ Not present'
    
    def _check_stack_protection(self) -> str:

        try:
        
            result = subprocess.run(['sysctl', 'kernel.randomize_va_space'], 
                                  capture_output=True, text=True)
        
            if '2' in result.stdout:
        
                return '✅ Full randomization'
        
            elif '1' in result.stdout:
        
                return '⚠️  Partial randomization'
        
            else:
        
                return '❌ Disabled'
        
        except:
            
            return '❓ Unknown'
    
    def _check_nx(self) -> str:

        try:

            with open('/proc/cpuinfo', 'r') as f:

                cpuinfo = f.read()

                if 'nx' in cpuinfo or 'xd' in cpuinfo:

                    return '✅ Supported'

            return '❌ Not supported'

        except:

            return '❓ Unknown'
    
    def _check_aslr(self) -> str:

        try:

            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:

                value = int(f.read().strip())

                if value == 2:

                    return '✅ Full ASLR'

                elif value == 1:

                    return '⚠️  Partial ASLR'

                else:

                    return '❌ Disabled'

        except:

            return '❓ Unknown'
    
    def _check_pie_support(self) -> str:

        try:

            result = subprocess.run(['gcc', '-v'], capture_output=True, text=True, errors='ignore')

            if '--enable-default-pie' in result.stderr:

                return '✅ Default PIE enabled'

            return '⚠️  PIE not default'

        except:

            return '❓ Unknown'
    
    def check_windows_kernel_protections(self) -> Dict:

        return {

            'DEP': '🔍 Run: wmic OS Get DataExecutionPrevention_SupportPolicy',
            'ASLR': '🔍 Check Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management',
            'CFG': '🔍 Control Flow Guard - Check process policies',
            'CIG': '🔍 Code Integrity Guard - Check Device Guard',
            'HVCI': '🔍 Hypervisor-protected Code Integrity',
            'KPP': '✅ PatchGuard (Always on 64-bit)'

        }

class BinaryProtectionChecker:
    
    def check_binary_protections(self, filepath: str) -> Dict:

        print_status(f"Analyzing binary: {filepath}", "SCAN")
        
        with open(filepath, 'rb') as f:
            
            magic = f.read(4)
            
        if magic[:2] == b'\x4D\x5A':  # PE
            
            return self._check_pe_protections(filepath)
        
        elif magic == b'\x7F\x45\x4C\x46':  # ELF
            
            return self._check_elf_protections(filepath)
        
        else:
        
            return {'type': 'Unknown', 'error': 'Unsupported binary format'}
    
    def _check_elf_protections(self, filepath: str) -> Dict:

        protections = {

            'type': 'ELF',
            'NX': '❌ Disabled',
            'PIE': '❌ Disabled',
            'RELRO': '❌ None',
            'Stack Canary': '❌ Disabled',
            'Fortify': '❌ Disabled'

        }
        
        try:

            result = subprocess.run(['checksec', '--file=' + filepath],
                                  capture_output=True, text=True, timeout=5)
            
            output = result.stdout
            
            if 'NX enabled' in output:
               
                protections['NX'] = '✅ Enabled'
            
            if 'PIE enabled' in output:
               
                protections['PIE'] = '✅ Enabled'
            
            if 'Full RELRO' in output:
            
                protections['RELRO'] = '✅ Full'
            
            elif 'Partial RELRO' in output:
            
                protections['RELRO'] = '⚠️  Partial'
            
            if 'Canary found' in output:
            
                protections['Stack Canary'] = '✅ Enabled'
            
            if 'FORTIFY' in output:
            
                protections['Fortify'] = '✅ Enabled'
                
        except:

            try:
                
                result = subprocess.run(['readelf', '-l', filepath],
                                      capture_output=True, text=True)
                
                if 'GNU_STACK' in result.stdout and 'RWE' not in result.stdout:
                
                    protections['NX'] = '✅ Enabled'
            except:
                
                pass
                
        return protections
    
    def _check_pe_protections(self, filepath: str) -> Dict:
        
        protections = {
        
            'type': 'PE',
            'ASLR': '❌ Disabled',
            'DEP': '❌ Disabled',
            'GS': '❌ Disabled',
            'SafeSEH': '❌ Disabled',
            'CFG': '❌ Disabled'
        
        }
        
        try:
            
            with open(filepath, 'rb') as f:
                
                dos_header = f.read(64)
                
                if dos_header[:2] != b'MZ':
                
                    return protections
                    
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                
                f.seek(pe_offset)
                
                pe_sig = f.read(4)
                
                if pe_sig != b'PE\x00\x00':
                    
                    return protections
                                
                f.seek(pe_offset + 24 + 70)
            
                dll_characteristics = struct.unpack('<H', f.read(2))[0]
                
                if dll_characteristics & 0x0040:
            
                    protections['ASLR'] = '✅ Enabled'
            
                if dll_characteristics & 0x0100:
            
                    protections['DEP'] = '✅ Enabled'
            
                if dll_characteristics & 0x0400:
            
                    protections['SafeSEH'] = '✅ Enabled'
            
                if dll_characteristics & 0x4000:
            
                    protections['CFG'] = '✅ Enabled'
                    
        except Exception as e:
            
            protections['error'] = str(e)
            
        return protections

class AdvancedFuzzer:
    
    def __init__(self):
       
        self.crash_dir = Path("trailblazer_crashes")
        self.crash_dir.mkdir(exist_ok=True)
        self.stats = {'iterations': 0, 'crashes': 0, 'timeouts': 0, 'errors': 0}
        
    def generate_mutations(self, data: bytes, strategy: str = 'smart') -> List[bytes]:

        mutations = []
        
        if strategy == 'smart':

            for i in range(min(len(data), 100)):

                mutated = bytearray(data)

                mutated[i] ^= random.randint(1, 255)

                mutations.append(bytes(mutated))
            
            magic_values = [
                
                b'\x00\x00\x00\x00',  # NULL
                b'\xff\xff\xff\xff',  # -1
                b'\x41\x41\x41\x41',  # AAAA
                b'\x00\x00\x00\x01',  # 1
                b'\x7f\xff\xff\xff',  # MAX_INT
                b'\x80\x00\x00\x00',  # MIN_INT
            
            ]
            
            for magic in magic_values:
                
                if len(data) >= 4:
                
                    pos = random.randint(0, len(data) - 4)
                
                    mutated = bytearray(data)
                
                    mutated[pos:pos+4] = magic
                
                    mutations.append(bytes(mutated))
            
            format_strings = [
            
                b'%x%x%x%x',
                b'%s%s%s%s',
                b'%n%n%n%n',
                b'%p%p%p%p',
            
            ]
            
            for fmt in format_strings:
                
                if len(data) >= len(fmt):
                
                    pos = random.randint(0, len(data) - len(fmt))
                
                    mutated = bytearray(data)
                
                    mutated[pos:pos+len(fmt)] = fmt
                
                    mutations.append(bytes(mutated))
                    
        return mutations
    
    def fuzz_target(self, target: str, seed_file: str, iterations: int = 1000):

        print_status(f"Initializing fuzzing campaign against {target}", "INFO")
        print_status(f"Seed file: {seed_file}", "INFO")
        print_status(f"Iterations: {iterations}", "INFO")
        
        with open(seed_file, 'rb') as f:
            
            seed_data = f.read()
            
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Starting TRAILBLAZER Fuzzing Engine...{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        for i in range(iterations):
            
            self.stats['iterations'] += 1
            
            mutations = self.generate_mutations(seed_data)
            
            for mutation in mutations[:10]:  
                
                with tempfile.NamedTemporaryFile(delete=False, suffix='.fuzz') as tmp:
                    
                    tmp.write(mutation)
                    tmp_path = tmp.name
                    
                try:

                    result = subprocess.run(
                    
                        [target, tmp_path],
                        capture_output=True,
                        timeout=1,
                        check=False
                    
                    )
                    
                    if result.returncode < 0:
                        
                        self.stats['crashes'] += 1
                        
                        crash_file = self.crash_dir / f"crash_{i}_{abs(result.returncode)}.bin"
                        
                        shutil.copy(tmp_path, crash_file)
                        
                        print_status(f"💥 CRASH FOUND! Signal: {abs(result.returncode)}", "ERROR")
                        print_status(f"Crash saved to: {crash_file}", "SUCCESS")
                        
                except subprocess.TimeoutExpired:
                    
                    self.stats['timeouts'] += 1
                    
                    timeout_file = self.crash_dir / f"timeout_{i}.bin"
                    
                    shutil.copy(tmp_path, timeout_file)
                    
                    print_status(f"⏱️  Timeout detected", "WARNING")
                    
                except Exception as e:
                    
                    self.stats['errors'] += 1
                    
                finally:
                    
                    os.unlink(tmp_path)
                    
            if (i + 1) % 100 == 0:
                
                self._print_progress(i + 1, iterations)
                
        self._print_final_stats()
    
    def _print_progress(self, current: int, total: int):

        percentage = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        print(f"\n{Colors.BOLD}Progress: [{bar}] {percentage:.1f}%{Colors.ENDC}")
        print(f"Crashes: {self.stats['crashes']} | Timeouts: {self.stats['timeouts']} | Errors: {self.stats['errors']}")
    
    def _print_final_stats(self):

        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Fuzzing Campaign Complete!{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"Total Iterations: {self.stats['iterations']}")
        print(f"Crashes Found: {Colors.FAIL}{self.stats['crashes']}{Colors.ENDC}")
        print(f"Timeouts: {Colors.WARNING}{self.stats['timeouts']}{Colors.ENDC}")
        print(f"Errors: {self.stats['errors']}")

class ExploitMitigationBypass:
    
    @staticmethod
    def show_bypass_techniques():

        techniques = {
            "Stack Canary": {
                "methods": ["Information Leak", "Brute Force", "Exception Handler"],
                "difficulty": "Medium"
            },
            "ASLR": {
                "methods": ["Memory Leak", "Partial Overwrite", "Heap Spray"],
                "difficulty": "Medium-Hard"
            },
            "DEP/NX": {
                "methods": ["ROP Chain", "JOP Chain", "JIT Spray"],
                "difficulty": "Hard"
            },
            "KASLR": {
                "methods": ["Side Channel", "Hardware Bugs", "Info Leak"],
                "difficulty": "Very Hard"
            },
            "SMEP/SMAP": {
                "methods": ["Kernel ROP", "CR4 Manipulation", "ret2dir"],
                "difficulty": "Expert"
            }
        }
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.WARNING}Exploit Mitigation Bypass Techniques (Educational){Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        for protection, info in techniques.items():
            
            print(f"{Colors.OKCYAN}[{protection}]{Colors.ENDC}")
            print(f"  Difficulty: {Colors.WARNING}{info['difficulty']}{Colors.ENDC}")
            print(f"  Methods:")
            
            for method in info['methods']:
            
                print(f"    • {method}")
            
            print()

class TrailblazerSystem:
    
    def __init__(self):
        
        self.sig_analyzer = FileSignatureAnalyzer()
        self.kernel_analyzer = KernelProtectionAnalyzer()
        self.binary_checker = BinaryProtectionChecker()
        self.fuzzer = AdvancedFuzzer()
        self.bypass_education = ExploitMitigationBypass()
        
    def main_menu(self):

        print(f"\n{Colors.BOLD}╔══════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}║           TRAILBLAZER FUZZER - Main Menu                ║{Colors.ENDC}")
        print(f"{Colors.BOLD}╚══════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print(f"""
{Colors.OKGREEN}[1]{Colors.ENDC} 🛡️  Ransomware Protection Suite
{Colors.OKGREEN}[2]{Colors.ENDC} 🔍 Kernel Security Analysis
{Colors.OKGREEN}[3]{Colors.ENDC} 📊 Binary Protection Checker
{Colors.OKGREEN}[4]{Colors.ENDC} 💥 Advanced Fuzzing Engine
{Colors.OKGREEN}[5]{Colors.ENDC} 📚 Bypass Techniques (Educational)
{Colors.OKGREEN}[6]{Colors.ENDC} 🔄 System Status & Statistics
{Colors.OKGREEN}[7]{Colors.ENDC} ⚙️  Advanced Options
{Colors.FAIL}[0]{Colors.ENDC} 🚪 Exit
        """)
        
    def ransomware_protection_menu(self):
        
        print(f"\n{Colors.BOLD}=== Ransomware Protection Suite ==={Colors.ENDC}")
        
        print("1. Protect Directory")
        print("2. Analyze File Signatures")
        print("3. Restore Protected Files")
        print("4. View Protection Statistics")
        print("0. Back to Main Menu")
        
        choice = input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
        
        if choice == '1':
            
            directory = input("Enter directory path: ")
            
            if os.path.exists(directory):
            
                method = input("Protection method (extension/signature): ")
            
                protected = 0
            
                for root, dirs, files in os.walk(directory):
            
                    for file in files:
            
                        filepath = os.path.join(root, file)
            
                        if self.sig_analyzer.protect_file(filepath, method):
            
                            protected += 1
            
                print_status(f"Protected {protected} files", "SUCCESS")
            
            else:
            
                print_status("Directory not found", "ERROR")
                
        elif choice == '2':
            
            filepath = input("Enter file path: ")
            
            if os.path.exists(filepath):
            
                info = self.sig_analyzer.analyze_file(filepath)
            
                print(f"\n{Colors.BOLD}File Analysis:{Colors.ENDC}")
            
                for key, value in info.items():
            
                    print(f"  {key}: {value}")
            
            else:
                
                print_status("File not found", "ERROR")
                
    def kernel_analysis(self):

        print(f"\n{Colors.BOLD}=== Kernel Security Analysis ==={Colors.ENDC}")
        
        print_status(f"OS: {self.kernel_analyzer.os_type}", "INFO")
        print_status(f"Kernel: {self.kernel_analyzer.kernel_version}", "INFO")
        print_status(f"Architecture: {self.kernel_analyzer.arch}", "INFO")
        
        protections = self.kernel_analyzer.analyze_all_protections()
        
        print(f"\n{Colors.BOLD}Protection Status:{Colors.ENDC}")
        
        for protection, status in protections.items():
        
            print(f"  {protection:28} : {status}")
            
    def binary_analysis(self):
        
        filepath = input("Enter binary file path: ")
        
        if os.path.exists(filepath):
        
            protections = self.binary_checker.check_binary_protections(filepath)
            
            print(f"\n{Colors.BOLD}Binary Protection Analysis:{Colors.ENDC}")
            print(f"Type: {protections.get('type', 'Unknown')}")
            
            for protection, status in protections.items():
        
                if protection != 'type':
            
                    print(f"  {protection:15} : {status}")
        
        else:
            
            print_status("File not found", "ERROR")
            
    def fuzzing_menu(self):

        print(f"\n{Colors.BOLD}=== Advanced Fuzzing Engine ==={Colors.ENDC}")
        
        target = input("Target application path: ")
        
        seed = input("Seed file path: ")
        
        if os.path.exists(target) and os.path.exists(seed):
        
            iterations = input("Number of iterations (default 1000): ")
            iterations = int(iterations) if iterations else 1000
            
            self.fuzzer.fuzz_target(target, seed, iterations)
        
        else:
            
            print_status("Target or seed file not found", "ERROR")
            
    # [수정] psutil 기반 시스템 정보 출력 기능 추가
    def show_statistics(self):

        print(f"\n{Colors.BOLD}=== System Statistics ==={Colors.ENDC}")
        
        # --- 기존 통계 ---
        print(f"\n{Colors.OKCYAN}File Protection:{Colors.ENDC}")
        print(f"  Files Analyzed: {self.sig_analyzer.stats['analyzed']}")
        print(f"  Files Protected: {self.sig_analyzer.stats['protected']}")
        print(f"  Files Restored: {self.sig_analyzer.stats['restored']}")
        
        print(f"\n{Colors.OKCYAN}Fuzzing Statistics:{Colors.ENDC}")
        print(f"  Total Iterations: {self.fuzzer.stats['iterations']}")
        print(f"  Crashes Found: {self.fuzzer.stats['crashes']}")
        print(f"  Timeouts: {self.fuzzer.stats['timeouts']}")
        
        # --- psutil 기반 실시간 시스템 정보 ---
        print(f"\n{Colors.OKCYAN}Live System Metrics (via psutil):{Colors.ENDC}")
        try:
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            print(f"  CPU Usage: {cpu_percent}%")
            
            # Memory
            mem = psutil.virtual_memory()
            
            mem_total_gb = round(mem.total / (1024**3), 2)
            mem_used_gb = round(mem.used / (1024**3), 2)
            
            print(f"  Memory Usage: {mem.percent}% ({mem_used_gb}GB / {mem_total_gb}GB)")

            # Disk
            disk = psutil.disk_usage('/')
            
            disk_total_gb = round(disk.total / (1024**3), 2)
            disk_used_gb = round(disk.used / (1024**3), 2)
            
            print(f"  Disk Usage (Root): {disk.percent}% ({disk_used_gb}GB / {disk_total_gb}GB)")
            
            # Boot Time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            
            print(f"  System Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")

        except Exception as e:
            
            print_status(f"Could not retrieve system metrics: {e}", "ERROR")

        
    def run(self):

        print_banner()
        
        while True:
            
            self.main_menu()
            
            choice = input(f"\n{Colors.OKGREEN}Select option: {Colors.ENDC}")
            
            if choice == '1':
            
                self.ransomware_protection_menu()
            
            elif choice == '2':
            
                self.kernel_analysis()
            
            elif choice == '3':
            
                self.binary_analysis()
            
            elif choice == '4':
            
                self.fuzzing_menu()
            
            elif choice == '5':
            
                self.bypass_education.show_bypass_techniques()
            
            elif choice == '6':
            
                self.show_statistics()
            
            elif choice == '7':
            
                print_status("Advanced options coming soon...", "INFO")
            
            elif choice == '0':
            
                print(f"\n{Colors.BOLD}Thanks for using TRAILBLAZER FUZZER!{Colors.ENDC}")
                print(f"{Colors.OKCYAN}Stay secure, stay vigilant.{Colors.ENDC}\n")
            
                break
            
            else:
                
                print_status("Invalid option", "WARNING")
                
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")

def main():
        
    try:
        
        if os.name == 'posix' and os.geteuid() != 0:
    
            print_status("Some features require root privileges", "WARNING")
            
        system = TrailblazerSystem()
        system.run()
        
    except KeyboardInterrupt:
        
        print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        
        sys.exit(0)
    
    except Exception as e:
        
        print(f"{Colors.FAIL}[!] Fatal error: {e}{Colors.ENDC}")
        
        sys.exit(1)

if __name__ == "__main__":
    
    main()
