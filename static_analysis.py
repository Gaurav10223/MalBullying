import pefile
import lief
import subprocess
import os
import sys
import re
import math
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict



def get_suspicious_patterns() -> Dict[str, List[str]]:
    """
    Define patterns for detecting suspicious strings.
    """
    return {
        'network': [
            r'https?://[a-zA-Z0-9\.\-/_]+',  # URLs
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
            r'\b[a-zA-Z0-9\-\.]+\.(com|net|org|ru|cn|info|bit|top|xyz)\b'  # Domains
        ],
        'filesystem': [
            r'C:\\[a-zA-Z0-9\\_\-\. ]+',  # Windows paths
            r'/[a-zA-Z0-9/_\-\.]+',  # Unix paths
            r'\.(exe|dll|bat|ps1|vbs|scr|cmd)\\?\b'  # Suspicious extensions
        ],
        'encryption': [
            r'(encrypt|decrypt|aes|rsa|rc4|base64)',
            r'[a-fA-F0-9]{32,}',  # Potential encryption keys or hashes
        ],
        'registry': [
            r'HKEY_[A-Z_]+\\[a-zA-Z0-9\\_\-]+',
            r'SOFTWARE\\Microsoft\\[a-zA-Z0-9\\_\-]+'
        ],
        'commands': [
            r'(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)',
            r'(whoami|netstat|tasklist|systeminfo|net\s+user)',
            r'(createprocess|createthread|virtualalloc|writeprocessmemory)'
        ],
        'ransomware': [
            r'(ransom|decrypt|bitcoin|payment|wallet)',
            r'README|DECRYPT|HOW_TO|YOUR_FILES',
            r'\.locked$|\.encrypted$|\.криптед$'
        ],
        'persistence': [
            r'(startup|schedule|task|service|autorun)',
            r'(HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)',
            r'(Windows\\System32\\Tasks)'
        ]
    }

def get_suspicious_dll_patterns() -> Dict[str, List[str]]:
    """
    Define patterns specific to DLL analysis.
    """
    return {
        'process_manipulation': [
            r'CreateRemoteThread',
            r'VirtualAlloc[Ex]?',
            r'WriteProcessMemory',
            r'LoadLibrary[A|W|Ex]?',
            r'GetProcAddress',
            r'VirtualProtect',
            r'HeapCreate',
            r'HeapAlloc'
        ],
        'injection_techniques': [
            r'SetWindowsHook[Ex]?',
            r'CreateThread',
            r'CreateProcess[A|W]?',
            r'NtCreateThread[Ex]?',
            r'RtlCreateUserThread',
            r'SetThreadContext'
        ],
        'network_activity': [
            r'WSAStartup',
            r'socket',
            r'connect',
            r'InternetOpen[A|W]?',
            r'InternetConnect[A|W]?',
            r'HttpOpenRequest[A|W]?',
            r'HttpSendRequest[A|W]?',
            r'URLDownloadToFile[A|W]?'
        ],
        'file_operations': [
            r'CreateFile[A|W]?',
            r'WriteFile',
            r'ReadFile',
            r'DeleteFile[A|W]?',
            r'CopyFile[A|W]?',
            r'MoveFile[A|W]?'
        ],
        'registry_operations': [
            r'RegCreate[Key|KeyEx][A|W]?',
            r'RegSet[Value|ValueEx][A|W]?',
            r'RegDelete[Key|Value][A|W]?',
            r'RegOpen[Key|KeyEx][A|W]?'
        ],
        'privilege_escalation': [
            r'AdjustTokenPrivileges',
            r'OpenProcessToken',
            r'LookupPrivilegeValue[A|W]?',
            r'GetTokenInformation'
        ],
        'anti_analysis': [
            r'IsDebuggerPresent',
            r'CheckRemoteDebuggerPresent',
            r'GetTickCount',
            r'QueryPerformanceCounter',
            r'OutputDebugString[A|W]?',
            r'GetSystemTime'
        ],
        'persistence': [
            r'RegSetValue[A|W]?.*\\Run',
            r'RegSetValue[A|W]?.*\\RunOnce',
            r'CreateService[A|W]?',
            r'StartService[A|W]?'
        ]
    }

def analyze_strings(strings_output: str) -> Dict[str, Set[str]]:
    """
    Analyze strings output for suspicious patterns.
    """
    patterns = get_suspicious_patterns()
    findings = {category: set() for category in patterns.keys()}
    
    for line in strings_output.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings[category].add(match.group())
    
    return findings

def analyze_dlls_and_functions(pe) -> Dict[str, List[Tuple[str, str]]]:
    """
    Analyze imported DLLs and their functions for suspicious patterns.
    """
    suspicious_patterns = get_suspicious_dll_patterns()
    findings = {category: [] for category in suspicious_patterns.keys()}
    
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    
                    for category, patterns in suspicious_patterns.items():
                        if any(re.search(pattern, func_name, re.IGNORECASE) for pattern in patterns):
                            findings[category].append((dll_name, func_name))
    except Exception as e:
        print(f"Error analyzing DLL imports: {e}")
    
    return findings

def check_dll_characteristics(pe) -> List[str]:
    """
    Check for suspicious DLL characteristics.
    """
    suspicious_chars = []
    
    try:
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
            suspicious_chars.append("Can be relocated at load time (DYNAMIC_BASE)")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400:
            suspicious_chars.append("No SEH handlers (NO_SEH)")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
            suspicious_chars.append("Compatible with data execution prevention (NX_COMPAT)")
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:
            suspicious_chars.append("Enables Control Flow Guard (GUARD_CF)")
            
    except Exception as e:
        print(f"Error checking DLL characteristics: {e}")
        
    return suspicious_chars

def analyze_dll_exports(pe) -> List[str]:
    """
    Analyze DLL exports for suspicious patterns.
    """
    suspicious_exports = []
    
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    suspicious_exports.append(f"Unnamed export at ordinal {exp.ordinal}")
                    continue
                
                name = exp.name.decode('utf-8')
                
                if re.match(r'^[0-9]+$', name):
                    suspicious_exports.append(f"Numeric-only export name: {name}")
                elif len(name) < 3:
                    suspicious_exports.append(f"Very short export name: {name}")
                elif re.match(r'^[a-zA-Z]{1,2}[0-9]+$', name):
                    suspicious_exports.append(f"Suspicious pattern export name: {name}")
                
    except Exception as e:
        print(f"Error analyzing DLL exports: {e}")
        
    return suspicious_exports

def extract_strings_with_floss(file_path):
    """
    Extract strings from the binary using FLARE FLOSS.
    If file is too large, falls back to alternative string extraction method.
    """
    import string  # Add import inside the function to ensure it's available

    # Check file size first
    file_size = os.path.getsize(file_path)
    size_limit = 0x1000000  # 16MB
    
    if file_size > size_limit:
        print(f"File size ({file_size} bytes) exceeds FLOSS limit ({size_limit} bytes).")
        print("Using alternative string extraction method...")
        
        # Alternative 1: Use built-in strings utility on Unix-like systems
        if os.name == 'posix':
            try:
                result = subprocess.check_output(['strings', file_path], 
                                              stderr=subprocess.PIPE,
                                              universal_newlines=True)
                return result
            except subprocess.CalledProcessError as e:
                print(f"Error running strings utility: {e}")
        
        # Alternative 2: Manual string extraction
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            printable = set(bytes(string.printable, 'ascii'))
            min_length = 4  # Minimum string length
            
            result = []
            current = []
            
            for byte in data:
                if byte in printable:
                    current.append(chr(byte))
                elif current:
                    if len(current) >= min_length:
                        result.append(''.join(current))
                    current = []
            
            if len(current) >= min_length:
                result.append(''.join(current))
            
            return '\n'.join(result)
        except Exception as e:
            print(f"Error extracting strings manually: {e}")
            return ""
    
    # If file size is within limits, use FLOSS
    floss_commands = ['floss', 'flarefloss', 'flare-floss']
    
    for command in floss_commands:
        try:
            result = subprocess.check_output([command, file_path], 
                                          stderr=subprocess.PIPE,
                                          universal_newlines=True)
            return result
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError as e:
            print(f"Error running {command}: {e}")
            print(f"STDERR: {e.stderr}")
            continue
    
    possible_paths = [
        Path.home() / '.local' / 'bin' / 'floss',
        Path('/usr/local/bin/floss'),
        Path('/usr/bin/floss'),
        Path(sys.prefix) / 'Scripts' / 'floss.exe',
        Path('flare-floss/floss.py'),
        # Add local enviroments
        Path('C:/Program Files/FLARE/floss.exe'),
        Path('C:/Program Files (x86)/FLARE/floss.exe'),
        Path('D:/Tools/FLARE/floss.exe'),
        Path('E:/FLARE/floss.exe'),
    ]
    
    for floss_path in possible_paths:
        if floss_path.exists():
            try:
                if floss_path.suffix == '.py':
                    result = subprocess.check_output(['python', str(floss_path), file_path],
                                                  stderr=subprocess.PIPE,
                                                  universal_newlines=True)
                else:
                    result = subprocess.check_output([str(floss_path), file_path],
                                                  stderr=subprocess.PIPE,
                                                  universal_newlines=True)
                return result
            except subprocess.CalledProcessError as e:
                print(f"Error running FLOSS at {floss_path}: {e}")
                print(f"STDERR: {e.stderr}")
                continue
    
    print("Could not find FLOSS installation. Please ensure FLOSS is installed correctly.")
    print("Installation instructions:")
    print("1. pip install flare-floss")
    print("   OR")
    print("2. Download from: https://github.com/mandiant/flare-floss/releases")
    return None

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return

    print(f"Analyzing: {file_path}")
    is_dll = pe.is_dll()
    
    # 1. Basic PE Header Analysis
    print("\n[PE HEADER]")
    print(f"Type: {'DLL' if is_dll else 'EXE'}")
    print(f"Number of Sections: {len(pe.sections)}")
    print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    print(f"Machine Type: {pe.FILE_HEADER.Machine}")

    # 2. DLL-specific Analysis (if applicable)
    if is_dll:
        print("\n[DLL CHARACTERISTICS]")
        dll_chars = check_dll_characteristics(pe)
        if dll_chars:
            print("Found the following DLL characteristics:")
            for char in dll_chars:
                print(f"  - {char}")
        
        print("\n[SUSPICIOUS EXPORTS]")
        suspicious_exports = analyze_dll_exports(pe)
        if suspicious_exports:
            print("Found suspicious exports:")
            for export in suspicious_exports:
                print(f"  - {export}")

    # 3. Section Analysis
    print("\n[SECTIONS]")
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        print(f"Section: {name}")
        print(f"Virtual Size: {hex(section.Misc_VirtualSize)}")
        print(f"Raw Size: {hex(section.SizeOfRawData)}")
        print(f"Virtual Address: {hex(section.VirtualAddress)}")
        entropy = section.get_entropy()
        print(f"Entropy: {entropy:.2f} {'(HIGH)' if entropy > 7.0 else ''}")
        print("----")

    # 4. Import Analysis
    print("\n[SUSPICIOUS IMPORTS ANALYSIS]")
    suspicious_imports = analyze_dlls_and_functions(pe)
    for category, findings in suspicious_imports.items():
        if findings:
            print(f"\n{category.upper()}:")
            for dll_name, func_name in findings:
                print(f"  - {dll_name}: {func_name}")

    # 5. String Analysis
    print("\n[EXTRACTING AND ANALYZING STRINGS USING FLOSS]")
    floss_results = extract_strings_with_floss(file_path)
    if floss_results:
        suspicious_findings = analyze_strings(floss_results)
        print("\n[SUSPICIOUS STRINGS ANALYSIS]")
        for category, findings in suspicious_findings.items():
            if findings:
                print(f"\n{category.upper()} Indicators:")
                for finding in sorted(findings):
                    print(f"  - {finding}")
    else:
        print("FLOSS analysis failed or produced no output.")

    # 6. Size and Import Analysis using LIEF
    print("\n[IMPORTS AND FILE SIZE COMPARISON]")
    try:
        binary = lief.parse(file_path)
        
        for section in binary.sections:
            print(f"Section: {section.name}")
            print(f"Raw Size: {section.size}")
            print(f"Virtual Size: {section.virtual_size}")
            diff = section.size - section.virtual_size
            print(f"Size Difference: {diff} {'(SUSPICIOUS)' if abs(diff) > 0x1000 else ''}")
        
        print("\n[DETAILED IMPORTS]")
        for imp in binary.imports:
            print(f"Imported DLL: {imp.name}")
            for entry in imp.entries:
                print(f"  Function: {entry.name}")
            print("----")
    except Exception as e:
        print(f"Error in LIEF analysis: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_file>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    if os.path.exists(file_path):
        analyze_pe_file(file_path)
    else:
        print(f"File {file_path} does not exist!")

class RiskScoring:
    def __init__(self):
        self.risk_factors = {
            'entropy': {
                'weight': 0.15,
                'thresholds': {
                    'high': 7.0,
                    'medium': 6.0,
                    'low': 5.0
                }
            },
            'suspicious_imports': {
                'weight': 0.20,
                'thresholds': {
                    'high': 10,
                    'medium': 5,
                    'low': 2
                }
            },
            'suspicious_strings': {
                'weight': 0.15,
                'thresholds': {
                    'high': 15,
                    'medium': 8,
                    'low': 3
                }
            },
            'section_characteristics': {
                'weight': 0.15,
                'thresholds': {
                    'high': 3,
                    'medium': 2,
                    'low': 1
                }
            },
            'anti_analysis': {
                'weight': 0.20,
                'thresholds': {
                    'high': 5,
                    'medium': 3,
                    'low': 1
                }
            },
            'ransomware_indicators': {
                'weight': 0.15,
                'thresholds': {
                    'high': 5,
                    'medium': 3,
                    'low': 1
                }
            }
        }
        
        self.ransomware_patterns = {
            'lockbit': [
                r'\.lockbit$',
                r'lock_file',
                r'encrypt_files',
                r'README\.txt',
                r'payment\.txt',
                r'restore-my-files\.'
            ],
            'akira': [
                r'\.akira$',
                r'akira_readme\.txt',
                r'recover_files',
                r'payment_instruction',
                r'encrypted\.akira$'
            ],
            'generic_ransomware': [
                r'\.(encrypted|locked|криптед)$',
                r'bitcoin_address',
                r'ransom_note',
                r'recover_files',
                r'payment_instructions'
            ]
        }
        
        self.anti_analysis_indicators = {
            'debugger_checks': [
                'IsDebuggerPresent',
                'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess'
            ],
            'timing_checks': [
                'QueryPerformanceCounter',
                'GetTickCount',
                'timeGetTime'
            ],
            'vm_detection': [
                'vmware',
                'virtualbox',
                'qemu',
                'xen'
            ],
            'sandbox_detection': [
                'sandbox',
                'sample',
                'virus',
                'malware'
            ]
        }

    def calculate_section_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a section."""
        if not data:
            return 0.0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def analyze_section_characteristics(self, pe) -> Dict[str, List[str]]:
        """Analyze section characteristics for suspicious indicators."""
        suspicious_sections = defaultdict(list)
        
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # Check for high entropy
            entropy = self.calculate_section_entropy(section.get_data())
            if entropy > 7.0:
                suspicious_sections['high_entropy'].append(name)
            
            # Check for executable sections
            if section.Characteristics & 0x20000000:
                suspicious_sections['executable'].append(name)
            
            # Check for writable and executable sections
            if (section.Characteristics & 0x80000000) and (section.Characteristics & 0x20000000):
                suspicious_sections['writable_executable'].append(name)
            
            # Check section size anomalies
            if section.Misc_VirtualSize > section.SizeOfRawData * 10:
                suspicious_sections['size_mismatch'].append(name)
            
        return suspicious_sections

    def check_anti_analysis_features(self, pe, strings_output: str) -> Dict[str, List[str]]:
        """Check for anti-analysis features in the binary."""
        anti_analysis_findings = defaultdict(list)
        
        # Check imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('utf-8')
                        for category, indicators in self.anti_analysis_indicators.items():
                            if any(indicator.lower() in name.lower() for indicator in indicators):
                                anti_analysis_findings[category].append(name)
        
        # Check strings
        for line in strings_output.split('\n'):
            for category, indicators in self.anti_analysis_indicators.items():
                if any(indicator.lower() in line.lower() for indicator in indicators):
                    anti_analysis_findings[category].append(line.strip())
        
        return anti_analysis_findings

    def calculate_risk_score(self, pe, suspicious_imports: Dict, suspicious_strings: Dict,
                           section_analysis: Dict, anti_analysis: Dict) -> Tuple[float, Dict[str, float]]:
        """Calculate overall risk score and individual component scores."""
        scores = {}
        
        # Entropy score
        # max_entropy = max(section.get_entropy() for section in pe.sections)
        # scores['entropy'] = min(max_entropy / self.risk_factors['entropy']['thresholds']['high'], 1.0)
        
        # Suspicious imports score
        import_count = sum(len(findings) for findings in suspicious_imports.values())
        scores['suspicious_imports'] = min(import_count / self.risk_factors['suspicious_imports']['thresholds']['high'], 1.0)
        
        # Suspicious strings score
        string_count = sum(len(findings) for findings in suspicious_strings.values())
        scores['suspicious_strings'] = min(string_count / self.risk_factors['suspicious_strings']['thresholds']['high'], 1.0)
        
        # Section characteristics score
        section_issues = sum(len(findings) for findings in section_analysis.values())
        scores['section_characteristics'] = min(section_issues / self.risk_factors['section_characteristics']['thresholds']['high'], 1.0)
        
        # Anti-analysis score
        anti_analysis_count = sum(len(findings) for findings in anti_analysis.values())
        scores['anti_analysis'] = min(anti_analysis_count / self.risk_factors['anti_analysis']['thresholds']['high'], 1.0)
        
        # Calculate final weighted score
        final_score = 0.0
        for category, score in scores.items():
            final_score += score * self.risk_factors[category]['weight']
        
        return final_score * 100, scores

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        risk_analyzer = RiskScoring()
        
        print(f"\n{'='*50}")
        print(f"ANALYZING: {file_path}")
        print(f"{'='*50}\n")
        
        # Perform existing analyses
        suspicious_imports = analyze_dlls_and_functions(pe)
        floss_results = extract_strings_with_floss(file_path)
        suspicious_strings = analyze_strings(floss_results) if floss_results else {}
        section_analysis = risk_analyzer.analyze_section_characteristics(pe)
        anti_analysis = risk_analyzer.check_anti_analysis_features(pe, floss_results if floss_results else "")
        
        # Calculate risk score
        risk_score, component_scores = risk_analyzer.calculate_risk_score(
            pe, suspicious_imports, suspicious_strings, section_analysis, anti_analysis
        )
        
        # Print detailed analysis results
        print("\n[RISK ANALYSIS SUMMARY]")
        print(f"Overall Risk Score: {risk_score:.2f}/100")
        print("\nComponent Scores:")
        for component, score in component_scores.items():
            print(f"- {component}: {score*100:.2f}%")
        
        # Print threat classification
        print("\n[THREAT CLASSIFICATION]")
        if risk_score >= 80:
            print("HIGH RISK - Exhibits strong indicators of malicious behavior")
        elif risk_score >= 60:
            print("MEDIUM RISK - Shows suspicious characteristics")
        else:
            print("LOW RISK - Limited suspicious indicators")
            
        # Continue with existing detailed analysis...
        print("\n[DETAILED ANALYSIS]")
        print_analysis_results(pe, suspicious_imports, suspicious_strings, 
                             section_analysis, anti_analysis)
        
    except Exception as e:
        print(f"Error analyzing file: {e}")
        return

def print_analysis_results(pe, suspicious_imports, suspicious_strings, 
                         section_analysis, anti_analysis):
    """Print detailed analysis results."""
    # Section Analysis
    print("\n[SECTION ANALYSIS]")
    for category, sections in section_analysis.items():
        if sections:
            print(f"\n{category.replace('_', ' ').title()}:")
            for section in sections:
                print(f"  - {section}")
    
    # Import Analysis
    print("\n[SUSPICIOUS IMPORTS]")
    for category, imports in suspicious_imports.items():
        if imports:
            print(f"\n{category.replace('_', ' ').title()}:")
            for dll, func in imports:
                print(f"  - {dll}: {func}")
    
    # String Analysis
    print("\n[SUSPICIOUS STRINGS]")
    for category, strings in suspicious_strings.items():
        if strings:
            print(f"\n{category.replace('_', ' ').title()}:")
            for string in strings:
                print(f"  - {string}")
    
    # Anti-Analysis Features
    print("\n[ANTI-ANALYSIS FEATURES]")
    for category, features in anti_analysis.items():
        if features:
            print(f"\n{category.replace('_', ' ').title()}:")
            for feature in features:
                print(f"  - {feature}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_file>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    if os.path.exists(file_path):
        analyze_pe_file(file_path)
    else:
        print(f"File {file_path} does not exist!")