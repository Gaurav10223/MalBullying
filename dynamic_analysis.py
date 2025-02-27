# import os
# import subprocess
# import time
# import psutil
# import hashlib
# import logging
# import tempfile
# import signal
# import re
# import platform
# import sys
# import codecs
# import shutil

# sys.stdout = codecs.getwriter("utf-32")(sys.stdout.buffer, 'replace')

# from pathlib import Path
# from datetime import datetime

# # Set up logging with file output
# log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
# os.makedirs(log_dir, exist_ok=True)
# log_file = os.path.join(log_dir, f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# # Configure logging to both file and console
# logging.basicConfig(
#     level=logging.INFO,
#     format='[%(asctime)s] %(levelname)s: %(message)s',
#     datefmt='%Y-%m-%d %H:%M:%S',
#     handlers=[
#         logging.FileHandler(log_file),
#         logging.StreamHandler(sys.stdout)
#     ]
# )
# logger = logging.getLogger()

# # High-risk system directories that should be protected
# PROTECTED_DIRECTORIES = [
#     r"C:\Windows\System32",
#     r"C:\Windows\SysWOW64",
#     r"C:\Program Files",
#     r"C:\Program Files (x86)",
#     r"C:\Windows\Boot",
#     r"C:\Windows\Fonts",
#     r"C:\Documents and Settings",
#     r"C:\Users\All Users",
# ]

# # Suspicious file operations patterns
# SUSPICIOUS_FILE_EXTENSIONS = [
#     ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".reg", ".sys"
# ]

# # Suspicious network connections
# SUSPICIOUS_PORTS = [4444, 1337, 31337, 8080, 443, 445, 3389] # Common C2 channels

# # Suspicous registry paths (Windows only)
# SUSPICIOUS_REGISTRY_PATHS = [
#     r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
#     r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
#     r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
#     r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
#     r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
# ]

# def calculate_file_hash(filepath):
#     """Calculate SHA256 hash of a file"""
#     try:
#         sha256_hash = hashlib.sha256()
#         with open(filepath, "rb") as f:
#             for byte_block in iter(lambda: f.read(4096), b""):
#                 sha256_hash.update(byte_block)
#         return sha256_hash.hexdigest()
#     except Exception as e:
#         logger.error(f"Error calculating hash for {filepath}: {e}")
#         return None

# def is_path_protected(path):
#     """Check if path is in a protected system directory"""
#     path = os.path.normpath(path)
#     return any(path.lower().startswith(protected.lower()) for protected in PROTECTED_DIRECTORIES)

# def is_file_operation_suspicious(filepath):
#     """Check if file operation is potentially malicious"""
#     if not filepath:
#         return False
    
#     # Check if it's modifying system files
#     if is_path_protected(filepath):
#         return True
    
#     # Check suspicious file extensions
#     file_ext = os.path.splitext(filepath)[1].lower()
#     if file_ext in SUSPICIOUS_FILE_EXTENSIONS:
#         return True
    
#     # Check for suspicious file names (encoded, temp files with executable content)
#     suspicious_patterns = [
#         r'\.tmp$|\.temp$', 
#         r'[a-f0-9]{32,}', # MD5/SHA patterns
#         r'^[a-zA-Z0-9]{8,10}\.[a-zA-Z0-9]{3}$' # Random names
#     ]
    
#     filename = os.path.basename(filepath)
#     for pattern in suspicious_patterns:
#         if re.search(pattern, filename):
#             return True
    
#     return False

# def is_network_connection_suspicious(addr_info):
#     """Check if a network connection might be malicious"""
#     if not addr_info or not hasattr(addr_info, 'port'):
#         return False
    
#     # Check for suspicious ports
#     if addr_info.port in SUSPICIOUS_PORTS:
#         return True
    
#     # Check for suspicious IP ranges (simplified)
#     if hasattr(addr_info, 'ip'):
#         ip = addr_info.ip
#         if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
#             # Usually local connections, less suspicious
#             return False
            
#     return False # Default to not suspicious

# def get_environment_info():
#     """Get information about the execution environment"""
#     env_info = {
#         "os": platform.system(),
#         "os_release": platform.release(),
#         "architecture": platform.architecture()[0],
#         "machine": platform.machine(),
#         "processor": platform.processor(),
#         "hostname": platform.node(),
#         "python_version": platform.python_version(),
#     }
#     return env_info

# def get_threat_level(score):
#     """Convert numeric threat score to a text level"""
#     if score >= 20:
#         return "CRITICAL"
#     elif score >= 10:
#         return "HIGH"
#     elif score >= 5:
#         return "MEDIUM"
#     else:
#         return "LOW"

# def print_risk_status_update(threat_score, threat_indicators, elapsed_time, max_indicators=3, first_run=False):
#     """Print real-time status update of the risk assessment with enhanced visual appeal and less space consumption"""
    
#     # Get terminal size
#     terminal_width, _ = shutil.get_terminal_size((80, 24))
    
#     # Choose color based on threat level
#     if threat_score >= 20:
#         level_color = "\033[91m"  # Red for critical
#         level_symbol = "⚠️"
#         level_text = "CRITICAL"
#     elif threat_score >= 10:
#         level_color = "\033[93m"  # Yellow for high
#         level_symbol = "⚠️"
#         level_text = "HIGH"
#     elif threat_score >= 5:
#         level_color = "\033[94m"  # Blue for medium
#         level_symbol = "ℹ️"
#         level_text = "MEDIUM"
#     else:
#         level_color = "\033[92m"  # Green for low
#         level_symbol = "✓"
#         level_text = "LOW"
    
#     reset_code = "\033[0m"
    
#     # Generate all lines first so we know how many lines we need
#     output_lines = []
    
#     # Header with status and elapsed time
#     header = f"{level_color}╭{'━' * (terminal_width - 2)}╮{reset_code}"
#     output_lines.append(header)
    
#     # Title line with threat level and score
#     title_text = f" {level_symbol} RISK ASSESSMENT [{level_text} RISK] • Score: {threat_score} • Time: {elapsed_time:.1f}s"
#     title_padding = terminal_width - len(title_text) - 14  # Account for color codes and symbols
#     title_line = f"{level_color}│{reset_code} {title_text}{' ' * title_padding}{level_color}│{reset_code}"
#     output_lines.append(title_line)
    
#     # Risk meter
#     meter_length = terminal_width - 8
#     filled_length = int(min(threat_score, 25) * meter_length / 25)
    
#     meter_text = f"{level_color}│{reset_code} "
#     meter_bar = f"[{level_color}{'█' * filled_length}{reset_code}{'▒' * (meter_length - filled_length)}]"
#     meter_line = f"{meter_text}{meter_bar} {level_color}│{reset_code}"
#     output_lines.append(meter_line)
    
#     # Separator line
#     if threat_indicators:
#         separator = f"{level_color}├{'┄' * (terminal_width - 2)}┤{reset_code}"
#         output_lines.append(separator)
        
#         # Threat indicators (limit to max_indicators to save space)
#         sorted_indicators = sorted(set(threat_indicators))[:max_indicators]
#         for indicator in sorted_indicators:
#             # Truncate long indicators to fit terminal width
#             max_indicator_length = terminal_width - 6
#             if len(indicator) > max_indicator_length:
#                 indicator = indicator[:max_indicator_length-3] + "..."
            
#             indicator_line = f"{level_color}│{reset_code} • {indicator}{' ' * (terminal_width - len(indicator) - 6)}{level_color}│{reset_code}"
#             output_lines.append(indicator_line)
        
#         # Show count of hidden indicators if needed
#         if len(threat_indicators) > max_indicators:
#             more_text = f"• +{len(threat_indicators) - max_indicators} more threats detected..."
#             more_line = f"{level_color}│{reset_code} {more_text}{' ' * (terminal_width - len(more_text) - 4)}{level_color}│{reset_code}"
#             output_lines.append(more_line)
    
#     # Footer
#     footer = f"{level_color}╰{'━' * (terminal_width - 2)}╯{reset_code}"
#     output_lines.append(footer)
    
#     # If first run, just print normally
#     if first_run:
#         print("\n".join(output_lines))
#         return len(output_lines)
    
#     # Move cursor up to redraw over previous output
#     print(f"\033[{len(output_lines)}A", end="")
    
#     # Print each line with a carriage return to clear line
#     for line in output_lines:
#         print(f"\r{line}")
    
#     return len(output_lines)

# def spinner_animation():
#     """Returns an iterator for spinner animation frames"""
#     frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
#     while True:
#         for frame in frames:
#             yield frame

# def monitor_process_activity(executable_path, minimum_monitor_time=60, sandbox_mode=True, update_interval=0.5):
#     """
#     Monitor a potentially malicious executable with protection mechanisms
    
#     Args:
#         executable_path: Path to the executable to monitor
#         minimum_monitor_time: Minimum time in seconds to monitor
#         sandbox_mode: If True, run with additional restrictions
#         update_interval: How often to update the real-time risk score display (seconds)
#     """
#     # Record analysis start time
#     analysis_start_time = datetime.now()
    
#     # Environment information
#     env_info = get_environment_info()
#     logger.info(f"[SYSTEM INFO] {env_info}")
    
#     # Sandbox preparation
#     logger.info("[+] Preparing secure monitoring environment...")
    
#     # Get file info before execution
#     file_info = {
#         "path": os.path.abspath(executable_path),
#         "size": os.path.getsize(executable_path),
#         "created": datetime.fromtimestamp(os.path.getctime(executable_path)).isoformat(),
#         "modified": datetime.fromtimestamp(os.path.getmtime(executable_path)).isoformat(),
#     }
#     logger.info(f"[FILE INFO] {file_info}")
    
#     # Get the initial hash before execution
#     try:
#         initial_hash = calculate_file_hash(executable_path)
#         logger.info(f"[+] Initial file hash (SHA256): {initial_hash}")
#     except Exception as e:
#         logger.error(f"[-] Error calculating initial hash: {e}")
#         return
    
#     # Threat score to track suspicious behaviors
#     threat_score = 0
#     threat_indicators = []
    
#     logger.info(f"[+] Starting monitoring of potentially malicious executable: {executable_path}")
#     logger.info(f"[*] Will monitor for at least {minimum_monitor_time} seconds")
#     logger.info(f"[*] Sandbox mode: {'Enabled' if sandbox_mode else 'Disabled'}")
#     logger.warning("[!] CAUTION: This executable may contain malware and could attempt to perform harmful actions")
    
#     # Tracking variables for monitoring
#     accessed_files = set()
#     modified_files = set()
#     suspicious_files_accessed = set()
#     suspicious_files_modified = set()
#     network_connections = set()
#     suspicious_connections = set()
#     child_processes = set()
#     events_timeline = []
    
#     # Variables for controlling real-time updates
#     last_update_time = time.time()
#     last_update_score = -1  # To ensure first update is always printed
    
#     # Get spinner animation generator
#     spinner = spinner_animation()
    
#     # Store the number of lines the status takes for cursor repositioning
#     status_lines = 0
    
#     try:
#         # Start the process with restricted permissions if possible
#         start_time = time.time()
#         monitor_until = start_time + minimum_monitor_time
        
#         process_args = [executable_path]
#         process_kwargs = {
#             'stdout': subprocess.PIPE,
#             'stderr': subprocess.PIPE,
#         }
        
#         # For Windows, we could add job object restrictions here in a full implementation
        
#         logger.info("[+] Launching process in controlled environment...")
#         process = subprocess.Popen(process_args, **process_kwargs)
#         pid = process.pid
#         logger.info(f"[+] Process started with PID: {pid}")
        
#         # Print initial risk status (first run)
#         status_lines = print_risk_status_update(threat_score, threat_indicators, 0.0, first_run=True)
        
#         # Event recording function
#         def record_event(event_type, description, severity="INFO"):
#             timestamp = time.time()
#             events_timeline.append({
#                 "timestamp": timestamp,
#                 "relative_time": timestamp - start_time,
#                 "type": event_type,
#                 "description": description,
#                 "severity": severity
#             })
#             if severity == "WARNING":
#                 logger.warning(f"[!] {description}")
#             elif severity == "CRITICAL":
#                 logger.critical(f"[!!!] {description}")
#             else:
#                 logger.info(f"[*] {description}")
        
#         # Record process start
#         record_event("PROCESS_START", f"Process started with PID {pid}")
        
#         # Continuous monitoring
#         try:
#             process_active = True
#             termination_triggered = False
            
#             while time.time() < monitor_until or (process_active and psutil.pid_exists(pid)):
#                 current_time = time.time()
#                 elapsed_time = current_time - start_time
                
#                 # Update risk status if score changed or update interval elapsed
#                 # Instead of clear screen, we use ANSI escape codes to move cursor
#                 if (threat_score != last_update_score or 
#                     current_time - last_update_time >= update_interval):
                    
#                     status_lines = print_risk_status_update(threat_score, threat_indicators, elapsed_time)
#                     last_update_time = current_time
#                     last_update_score = threat_score
                
#                 if psutil.pid_exists(pid) and not termination_triggered:
#                     try:
#                         proc = psutil.Process(pid)
#                         process_active = True
                        
#                         # Check CPU and memory usage for unusual behavior
#                         try:
#                             cpu_percent = proc.cpu_percent(interval=0.1)
#                             memory_percent = proc.memory_percent()
                            
#                             if cpu_percent > 80:
#                                 threat_score += 2
#                                 record_event("HIGH_CPU", f"High CPU usage detected: {cpu_percent}%", "WARNING")
#                                 threat_indicators.append(f"High CPU usage ({cpu_percent}%)")
                            
#                             if memory_percent > 15:
#                                 threat_score += 2
#                                 record_event("HIGH_MEMORY", f"High memory usage detected: {memory_percent}%", "WARNING")
#                                 threat_indicators.append(f"High memory usage ({memory_percent}%)")
#                         except (psutil.AccessDenied, psutil.NoSuchProcess):
#                             pass
                        
#                         # Monitor open files
#                         try:
#                             open_files = proc.open_files()
#                             for file in open_files:
#                                 filepath = file.path
                                
#                                 # Track regular file access
#                                 if filepath not in accessed_files:
#                                     accessed_files.add(filepath)
#                                     record_event("FILE_ACCESS", f"File accessed: {filepath}")
                                
#                                 # Check for suspicious file access
#                                 if is_file_operation_suspicious(filepath) and filepath not in suspicious_files_accessed:
#                                     suspicious_files_accessed.add(filepath)
#                                     threat_score += 3
#                                     record_event("SUSPICIOUS_FILE_ACCESS", 
#                                                 f"SUSPICIOUS file access detected: {filepath}", 
#                                                 "WARNING")
#                                     threat_indicators.append(f"Suspicious file access: {filepath}")
                                
#                                 # Check if files are modified
#                                 if os.path.exists(filepath):
#                                     try:
#                                         mtime = os.path.getmtime(filepath)
#                                         if mtime > start_time and filepath not in modified_files:
#                                             modified_files.add(filepath)
#                                             record_event("FILE_MODIFY", f"File modified: {filepath}")
                                            
#                                             # Check if modification is suspicious
#                                             if is_file_operation_suspicious(filepath) and filepath not in suspicious_files_modified:
#                                                 suspicious_files_modified.add(filepath)
#                                                 threat_score += 5
#                                                 record_event("SUSPICIOUS_FILE_MODIFY", 
#                                                            f"SUSPICIOUS file modification detected: {filepath}", 
#                                                            "CRITICAL")
#                                                 threat_indicators.append(f"Suspicious file modification: {filepath}")
                                            
#                                             # If modifying system files and sandbox mode is on, consider termination
#                                             if is_path_protected(filepath) and sandbox_mode:
#                                                 threat_score += 10
#                                                 record_event("SYSTEM_FILE_MODIFY", 
#                                                            f"CRITICAL: Attempting to modify system file: {filepath}. "
#                                                            f"Process will be terminated.", 
#                                                            "CRITICAL")
#                                                 threat_indicators.append(f"System file modification attempt: {filepath}")
#                                                 termination_triggered = True
#                                                 break
#                                     except Exception:
#                                         pass
#                         except (psutil.AccessDenied, psutil.NoSuchProcess):
#                             pass
                        
#                         # Monitor network connections
#                         try:
#                             connections = proc.net_connections()
#                             for conn in connections:
#                                 if conn.status == 'ESTABLISHED' and hasattr(conn.raddr, 'ip'):
#                                     conn_info = f"{conn.raddr.ip}:{conn.raddr.port}"
#                                     if conn_info not in network_connections:
#                                         network_connections.add(conn_info)
#                                         record_event("NETWORK_CONNECTION", f"Network connection established to {conn_info}")
                                        
#                                         # Check if connection is suspicious
#                                         if is_network_connection_suspicious(conn.raddr) and conn_info not in suspicious_connections:
#                                             suspicious_connections.add(conn_info)
#                                             threat_score += 4
#                                             record_event("SUSPICIOUS_CONNECTION", 
#                                                       f"SUSPICIOUS network connection detected to {conn_info}", 
#                                                       "WARNING")
#                                             threat_indicators.append(f"Suspicious network connection: {conn_info}")
#                         except (psutil.AccessDenied, psutil.NoSuchProcess):
#                             pass
                        
#                         # Monitor child processes
#                         try:
#                             children = proc.children(recursive=True)
#                             for child in children:
#                                 try:
#                                     child_info = f"{child.name()} (PID: {child.pid})"
#                                     if child_info not in child_processes:
#                                         child_processes.add(child_info)
#                                         threat_score += 3
#                                         record_event("CHILD_PROCESS", f"Child process created: {child_info}", "WARNING")
#                                         threat_indicators.append(f"Created child process: {child_info}")
#                                 except (psutil.AccessDenied, psutil.NoSuchProcess):
#                                     pass
#                         except (psutil.AccessDenied, psutil.NoSuchProcess):
#                             pass
                            
#                         # Check for self-deletion attempts
#                         if not os.path.exists(executable_path) and not termination_triggered:
#                             threat_score += 10
#                             record_event("SELF_DELETION", 
#                                        "CRITICAL: Malware attempted to delete itself (anti-analysis technique)", 
#                                        "CRITICAL")
#                             threat_indicators.append("Self-deletion attempt")
#                             termination_triggered = True
                        
#                         # Terminate process if threat score is too high or critical violations detected
#                         if (threat_score >= 15 or termination_triggered) and sandbox_mode:
#                             reason = "high threat score" if threat_score >= 15 else "critical violation"
#                             record_event("PROTECTION_TRIGGERED", 
#                                        f"SECURITY ALERT: Terminating process due to {reason} ({threat_score})", 
#                                        "CRITICAL")
                            
#                             try:
#                                 logger.critical("[!!!] SECURITY PROTECTION TRIGGERED - TERMINATING MALICIOUS PROCESS")
                                
#                                 # Kill the process tree
#                                 parent = psutil.Process(pid)
#                                 children = parent.children(recursive=True)
#                                 for child in children:
#                                     try:
#                                         child.kill()
#                                     except:
#                                         pass
#                                 parent.kill()
                                
#                                 process_active = False
#                                 logger.info("[+] Process terminated successfully for security reasons")
#                             except Exception as e:
#                                 logger.error(f"[-] Failed to terminate process: {e}")
                    
#                     except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
#                         logger.warning(f"[-] Lost access to process: {e}")
#                         if not psutil.pid_exists(pid):
#                             process_active = False
#                             record_event("PROCESS_EXIT", "Process terminated on its own")
#                 else:
#                     if process_active and not psutil.pid_exists(pid):
#                         process_active = False
#                         record_event("PROCESS_EXIT", "Process terminated on its own")
                
#                 # Sleep briefly between checks
#                 time.sleep(0.2)
                
#         except KeyboardInterrupt:
#             logger.info("\n[+] Monitoring stopped by user")
#             record_event("USER_INTERRUPT", "Monitoring stopped by user")
        
#         # Ensure process is terminated
#         if psutil.pid_exists(pid):
#             try:
#                 proc = psutil.Process(pid)
#                 logger.info("[+] Cleaning up: terminating process...")
                
#                 # Kill process tree
#                 children = proc.children(recursive=True)
#                 for child in children:
#                     try:
#                         child.kill()
#                     except:
#                         pass
#                 proc.kill()
                
#                 logger.info("[+] Process terminated")
#             except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
#                 logger.warning(f"[-] Could not terminate process: {e}")
        
#         # Print final newline to separate from summary
#         print("\n")
        
#         # Check if the executable's hash has changed
#         try:
#             if os.path.exists(executable_path):
#                 final_hash = calculate_file_hash(executable_path)
#                 if final_hash != initial_hash:
#                     threat_score += 8
#                     logger.critical(f"[!!!] CRITICAL: Executable hash changed from {initial_hash} to {final_hash}")
#                     threat_indicators.append("Executable self-modification")
#                 else:
#                     logger.info(f"[+] Executable hash remained unchanged: {final_hash}")
#             else:
#                 logger.critical("[!!!] CRITICAL: Executable has been deleted during execution")
#                 threat_indicators.append("Executable self-deletion")
#                 threat_score += 8
#         except Exception as e:
#             logger.error(f"[-] Error calculating final hash: {e}")
        
#         # Generate threat assessment
#         threat_level = get_threat_level(threat_score)
        
#         # Analysis summary
#         analysis_duration = time.time() - start_time
        
#         # Print a summary box
#         terminal_width, _ = shutil.get_terminal_size((80, 24))
        
#         # Create a stylish summary box
#         print("\n" + "╔" + "═"*(terminal_width-2) + "╗")
#         print("║" + f"{'MALWARE ANALYSIS SUMMARY':^{terminal_width-2}}" + "║")
#         print("╠" + "═"*(terminal_width-2) + "╣")
        
#         # Choose color for threat level
#         if threat_level == "CRITICAL":
#             level_color = "\033[91m"  # Red
#         elif threat_level == "HIGH":
#             level_color = "\033[93m"  # Yellow
#         elif threat_level == "MEDIUM":
#             level_color = "\033[94m"  # Blue
#         else:
#             level_color = "\033[92m"  # Green
        
#         reset_code = "\033[0m"
        
#         # Basic info
#         print("║" + f" Analysis completed in {analysis_duration:.2f} seconds".ljust(terminal_width-2) + "║")
#         print("║" + f" Sample: {os.path.basename(executable_path)}".ljust(terminal_width-2) + "║")
#         print("║" + f" SHA256: {initial_hash}".ljust(terminal_width-2) + "║")
#         print("║" + f" Threat assessment: {level_color}{threat_level}{reset_code} (Score: {threat_score})".ljust(terminal_width-2) + "║")
        
#         # Threat indicators
#         if threat_indicators:
#             print("║" + "─"*(terminal_width-2) + "║")
#             print("║" + " Threat indicators detected:".ljust(terminal_width-2) + "║")
            
#             # Display indicators sorted by importance
#             for i, indicator in enumerate(sorted(set(threat_indicators))[:10], 1):
#                 # Truncate long indicators to fit
#                 if len(indicator) > terminal_width - 7:  # Account for "║ N. " prefix and "║" suffix
#                     indicator = indicator[:terminal_width-10] + "..."
                
#                 print("║" + f" {i}. {indicator}".ljust(terminal_width-2) + "║")
            
#             if len(threat_indicators) > 10:
#                 print("║" + f" ... and {len(set(threat_indicators)) - 10} more".ljust(terminal_width-2) + "║")
        
#         # Statistics
#         print("║" + "─"*(terminal_width-2) + "║")
#         print("║" + " Activity statistics:".ljust(terminal_width-2) + "║")
#         print("║" + f" Files accessed: {len(accessed_files)} | Modified: {len(modified_files)}".ljust(terminal_width-2) + "║")
#         print("║" + f" Suspicious files: {len(suspicious_files_accessed)} accessed, {len(suspicious_files_modified)} modified".ljust(terminal_width-2) + "║")
#         print("║" + f" Network connections: {len(network_connections)} | Suspicious: {len(suspicious_connections)}".ljust(terminal_width-2) + "║")
#         print("║" + f" Child processes spawned: {len(child_processes)}".ljust(terminal_width-2) + "║")
        
#         # Log file info
#         print("║" + "─"*(terminal_width-2) + "║")
#         print("║" + f" Analysis log saved to: {log_file}".ljust(terminal_width-2) + "║")
#         print("╚" + "═"*(terminal_width-2) + "╝")
        
#         # Log the full details
#         logger.info("\n" + "="*80)
#         logger.info("MALWARE ANALYSIS SUMMARY")
#         logger.info("="*80)
#         logger.info(f"Analysis completed in {analysis_duration:.2f} seconds")
#         logger.info(f"Sample: {os.path.basename(executable_path)}")
#         logger.info(f"SHA256: {initial_hash}")
#         logger.info(f"Threat assessment: {threat_level} (Score: {threat_score})")
        
#         if threat_indicators:
#             logger.info("\nThreat indicators detected:")
#             for i, indicator in enumerate(sorted(set(threat_indicators)), 1):
#                 logger.info(f" {i}. {indicator}")
        
#         logger.info("\nActivity statistics:")
#         logger.info(f" Total files accessed: {len(accessed_files)}")
#         logger.info(f" Suspicious files accessed: {len(suspicious_files_accessed)}")
#         logger.info(f" Files modified: {len(modified_files)}")
#         logger.info(f" Suspicious files modified: {len(suspicious_files_modified)}")
#         logger.info(f" Network connections: {len(network_connections)}")
#         logger.info(f" Suspicious network connections: {len(suspicious_connections)}")
#         logger.info(f" Child processes spawned: {len(child_processes)}")
        
#         # Detailed logs section
#         if suspicious_files_accessed:
#             logger.info("\nSuspicious files accessed:")
#             for file in sorted(suspicious_files_accessed):
#                 logger.info(f" - {file}")
        
#         if suspicious_files_modified:
#             logger.info("\nSuspicious files modified:")
#             for file in sorted(suspicious_files_modified):
#                 logger.info(f" - {file}")
        
#         if suspicious_connections:
#             logger.info("\nSuspicious network connections:")
#             for conn in sorted(suspicious_connections):
#                 logger.info(f" - {conn}")
        
#         if child_processes:
#             logger.info("\nChild processes:")
#             for proc in sorted(child_processes):
#                 logger.info(f" - {proc}")
        
#         logger.info("\nAnalysis log saved to:")
#         logger.info(f" {log_file}")
#         logger.info("="*80)
        
#         return {
#             "threat_score": threat_score,
#             "threat_level": threat_level,
#             "threat_indicators": threat_indicators,
#             "analysis_duration": analysis_duration,
#             "log_file": log_file
#         }
        
#     except Exception as e:
#         logger.error(f"[-] Error during malware monitoring: {e}")
#         return None

# if __name__ == "__main__":
#     import argparse
    
#     parser = argparse.ArgumentParser(description="Malware Behavior Monitoring Tool")
#     parser.add_argument("--target", "-t", required=True,
#                       help="Path to the suspicious executable to monitor")
#     parser.add_argument("--time", "-m", type=int, default=60,
#                       help="Minimum monitoring time in seconds")
#     parser.add_argument("--sandbox", "-s", action="store_true", default=True,
#                       help="Enable sandbox mode with additional protections")
#     parser.add_argument("--output", "-o", type=str,
#                       help="Output directory for analysis reports")
#     parser.add_argument("--verbose", "-v", action="store_true",
#                       help="Enable verbose output with more details")
    
#     args = parser.parse_args()
    
#     # Validate that the target file exists
#     if not os.path.exists(args.target):
#         logger.error(f"[-] Target file not found: {args.target}")
#         sys.exit(1)
    
#     # Set up custom output directory if specified
#     if args.output:
#         custom_output_dir = os.path.abspath(args.output)
#         os.makedirs(custom_output_dir, exist_ok=True)
#         # Update log file path
#         log_file = os.path.join(custom_output_dir, f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
#         # Reconfigure logging to use new path
#         for handler in logger.handlers[:]:
#             if isinstance(handler, logging.FileHandler):
#                 handler.close()
#                 logger.removeHandler(handler)
#         logger.addHandler(logging.FileHandler(log_file))
    
#     # Set log level based on verbosity
#     if args.verbose:
#         logger.setLevel(logging.DEBUG)
#         logger.debug("[+] Verbose logging enabled")
    
#     try:
#         print(f"\n[*] Starting analysis of: {os.path.basename(args.target)}")
#         print(f"[*] Monitoring for at least {args.time} seconds")
#         print(f"[*] Sandbox protections: {'Enabled' if args.sandbox else 'Disabled'}")
#         print("\n[!] CAUTION: Running potentially malicious code. Do not use on production systems.\n")
        
#         # Brief pause to let user read the warning
#         time.sleep(1)
        
#         # Replace the fancy display functions with simpler versions
#         # We'll need to modify the monitor_process_activity function when calling it
        
#         print("[*] Analysis in progress. Please wait...")
        
#         # Override the print_risk_status_update function to do nothing
#         def simple_status_update(threat_score, threat_indicators, elapsed_time, max_indicators=3, first_run=False):
#             # No fancy display
#             return 0
        
#         # Store the original function
#         original_print_risk = globals()['print_risk_status_update']
#         # Replace with our simple version
#         globals()['print_risk_status_update'] = simple_status_update
        
#         # Run the monitoring function
#         results = monitor_process_activity(
#             executable_path=args.target,
#             minimum_monitor_time=args.time,
#             sandbox_mode=args.sandbox,
#             update_interval=5.0  # Less frequent updates since we're not showing real-time display
#         )
        
#         # Restore the original function (though it won't be used anymore)
#         globals()['print_risk_status_update'] = original_print_risk
        
#         if results:
#             # Print a simple summary instead of the fancy box
#             print("\n" + "="*50)
#             print(" MALWARE ANALYSIS SUMMARY")
#             print("="*50)
#             print(f"Analysis completed in {results['analysis_duration']:.2f} seconds")
#             print(f"Threat level: {results['threat_level']} (Score: {results['threat_score']})")
            
#             if results['threat_indicators']:
#                 print("\nThreat indicators detected:")
#                 for i, indicator in enumerate(sorted(set(results['threat_indicators'])), 1):
#                     print(f" {i}. {indicator}")
            
#             print(f"\nDetailed log saved to: {results['log_file']}")
#             print("="*50)
            
#             sys.exit(0 if results["threat_level"] in ["LOW", "MEDIUM"] else 1)
#         else:
#             logger.error("[-] Analysis failed to complete")
#             sys.exit(2)
            
#     except KeyboardInterrupt:
#         print("\n[!] Analysis interrupted by user")
#         sys.exit(130)
#     except Exception as e:
#         logger.error(f"[-] Unhandled exception: {e}")
#         sys.exit(1)

import os
import subprocess
import time
import psutil
import hashlib
import logging
import tempfile
import signal
import re
import platform
import sys
from pathlib import Path
from datetime import datetime

# Set up logging with file output
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

# High-risk system directories that should be protected
PROTECTED_DIRECTORIES = [
    f"C:\\Windows\\System32",
    f"C:\\Windows\\SysWOW64",
    f"C:\\Program Files",
    f"C:\\Program Files (x86)",
    f"C:\\Windows\\Boot",
    f"C:\\Windows\\Fonts",
    f"C:\\Documents and Settings",
    f"C:\\Users\\All Users",
]

# Suspicious file operations patterns
SUSPICIOUS_FILE_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".reg", ".sys"
]

# Suspicious network connections
SUSPICIOUS_PORTS = [4444, 1337, 31337, 8080, 443, 445, 3389]  # Common C2 channels

# Suspicous registry paths (Windows only)
SUSPICIOUS_REGISTRY_PATHS = [
    f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    f"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    f"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    f"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
]

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {filepath}: {e}")
        return None

def is_path_protected(path):
    """Check if path is in a protected system directory"""
    path = os.path.normpath(path)
    return any(path.lower().startswith(protected.lower()) for protected in PROTECTED_DIRECTORIES)

def is_file_operation_suspicious(filepath):
    """Check if file operation is potentially malicious"""
    if not filepath:
        return False
    
    # Check if it's modifying system files
    if is_path_protected(filepath):
        return True
    
    # Check suspicious file extensions
    file_ext = os.path.splitext(filepath)[1].lower()
    if file_ext in SUSPICIOUS_FILE_EXTENSIONS:
        return True
    
    # Check for suspicious file names (encoded, temp files with executable content)
    suspicious_patterns = [
        r'\.tmp$|\.temp$', 
        r'[a-f0-9]{32,}',  # MD5/SHA patterns
        r'^[a-zA-Z0-9]{8,10}\.[a-zA-Z0-9]{3}$'  # Random names
    ]
    
    filename = os.path.basename(filepath)
    for pattern in suspicious_patterns:
        if re.search(pattern, filename):
            return True
    
    return False

def is_network_connection_suspicious(addr_info):
    """Check if a network connection might be malicious"""
    if not addr_info or not hasattr(addr_info, 'port'):
        return False
    
    # Check for suspicious ports
    if addr_info.port in SUSPICIOUS_PORTS:
        return True
    
    # Check for suspicious IP ranges (simplified)
    if hasattr(addr_info, 'ip'):
        ip = addr_info.ip
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            # Usually local connections, less suspicious
            return False
            
    return False  # Default to not suspicious

def get_environment_info():
    """Get information about the execution environment"""
    env_info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.architecture()[0],
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
    }
    return env_info

def monitor_process_activity(executable_path, minimum_monitor_time=60, sandbox_mode=True):
    """
    Monitor a potentially malicious executable with protection mechanisms
    
    Args:
        executable_path: Path to the executable to monitor
        minimum_monitor_time: Minimum time in seconds to monitor
        sandbox_mode: If True, run with additional restrictions
    """
    # Record analysis start time
    analysis_start_time = datetime.now()
    
    # Environment information
    env_info = get_environment_info()
    logger.info(f"[SYSTEM INFO] {env_info}")
    
    # Sandbox preparation
    logger.info("[+] Preparing secure monitoring environment...")
    
    # Get file info before execution
    file_info = {
        "path": os.path.abspath(executable_path),
        "size": os.path.getsize(executable_path),
        "created": datetime.fromtimestamp(os.path.getctime(executable_path)).isoformat(),
        "modified": datetime.fromtimestamp(os.path.getmtime(executable_path)).isoformat(),
    }
    logger.info(f"[FILE INFO] {file_info}")
    
    # Get the initial hash before execution
    try:
        initial_hash = calculate_file_hash(executable_path)
        logger.info(f"[+] Initial file hash (SHA256): {initial_hash}")
    except Exception as e:
        logger.error(f"[-] Error calculating initial hash: {e}")
        return
    
    # Threat score to track suspicious behaviors
    threat_score = 0
    threat_indicators = []
    
    logger.info(f"[+] Starting monitoring of potentially malicious executable: {executable_path}")
    logger.info(f"[*] Will monitor for at least {minimum_monitor_time} seconds")
    logger.info(f"[*] Sandbox mode: {'Enabled' if sandbox_mode else 'Disabled'}")
    logger.warning("[!] CAUTION: This executable may contain malware and could attempt to perform harmful actions")
    
    # Tracking variables for monitoring
    accessed_files = set()
    modified_files = set()
    suspicious_files_accessed = set()
    suspicious_files_modified = set()
    network_connections = set()
    suspicious_connections = set()
    child_processes = set()
    events_timeline = []
    
    try:
        # Start the process with restricted permissions if possible
        start_time = time.time()
        monitor_until = start_time + minimum_monitor_time
        
        process_args = [executable_path]
        process_kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
        }
        
        # For Windows, we could add job object restrictions here in a full implementation
        
        logger.info("[+] Launching process in controlled environment...")
        process = subprocess.Popen(process_args, **process_kwargs)
        pid = process.pid
        logger.info(f"[+] Process started with PID: {pid}")
        
        # Event recording function
        def record_event(event_type, description, severity="INFO"):
            timestamp = time.time()
            events_timeline.append({
                "timestamp": timestamp,
                "relative_time": timestamp - start_time,
                "type": event_type,
                "description": description,
                "severity": severity
            })
            if severity == "WARNING":
                logger.warning(f"[!] {description}")
            elif severity == "CRITICAL":
                logger.critical(f"[!!!] {description}")
            else:
                logger.info(f"[*] {description}")
        
        # Record process start
        record_event("PROCESS_START", f"Process started with PID {pid}")
        
        # Continuous monitoring
        try:
            process_active = True
            termination_triggered = False
            
            while time.time() < monitor_until or (process_active and psutil.pid_exists(pid)):
                if psutil.pid_exists(pid) and not termination_triggered:
                    try:
                        proc = psutil.Process(pid)
                        process_active = True
                        
                        # Check CPU and memory usage for unusual behavior
                        try:
                            cpu_percent = proc.cpu_percent(interval=0.1)
                            memory_percent = proc.memory_percent()
                            
                            if cpu_percent > 80:
                                threat_score += 2
                                record_event("HIGH_CPU", f"High CPU usage detected: {cpu_percent}%", "WARNING")
                                threat_indicators.append(f"High CPU usage ({cpu_percent}%)")
                            
                            if memory_percent > 15:
                                threat_score += 2
                                record_event("HIGH_MEMORY", f"High memory usage detected: {memory_percent}%", "WARNING")
                                threat_indicators.append(f"High memory usage ({memory_percent}%)")
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        # Monitor open files
                        try:
                            open_files = proc.open_files()
                            for file in open_files:
                                filepath = file.path
                                
                                # Track regular file access
                                if filepath not in accessed_files:
                                    accessed_files.add(filepath)
                                    record_event("FILE_ACCESS", f"File accessed: {filepath}")
                                
                                # Check for suspicious file access
                                if is_file_operation_suspicious(filepath) and filepath not in suspicious_files_accessed:
                                    suspicious_files_accessed.add(filepath)
                                    threat_score += 3
                                    record_event("SUSPICIOUS_FILE_ACCESS", 
                                                f"SUSPICIOUS file access detected: {filepath}", 
                                                "WARNING")
                                    threat_indicators.append(f"Suspicious file access: {filepath}")
                                
                                # Check if files are modified
                                if os.path.exists(filepath):
                                    try:
                                        mtime = os.path.getmtime(filepath)
                                        if mtime > start_time and filepath not in modified_files:
                                            modified_files.add(filepath)
                                            record_event("FILE_MODIFY", f"File modified: {filepath}")
                                            
                                            # Check if modification is suspicious
                                            if is_file_operation_suspicious(filepath) and filepath not in suspicious_files_modified:
                                                suspicious_files_modified.add(filepath)
                                                threat_score += 5
                                                record_event("SUSPICIOUS_FILE_MODIFY", 
                                                           f"SUSPICIOUS file modification detected: {filepath}", 
                                                           "CRITICAL")
                                                threat_indicators.append(f"Suspicious file modification: {filepath}")
                                            
                                            # If modifying system files and sandbox mode is on, consider termination
                                            if is_path_protected(filepath) and sandbox_mode:
                                                threat_score += 10
                                                record_event("SYSTEM_FILE_MODIFY", 
                                                           f"CRITICAL: Attempting to modify system file: {filepath}. "
                                                           f"Process will be terminated.", 
                                                           "CRITICAL")
                                                threat_indicators.append(f"System file modification attempt: {filepath}")
                                                termination_triggered = True
                                                break
                                    except Exception:
                                        pass
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        # Monitor network connections
                        try:
                            connections = proc.net_connections()
                            for conn in connections:
                                if conn.status == 'ESTABLISHED' and hasattr(conn.raddr, 'ip'):
                                    conn_info = f"{conn.raddr.ip}:{conn.raddr.port}"
                                    if conn_info not in network_connections:
                                        network_connections.add(conn_info)
                                        record_event("NETWORK_CONNECTION", f"Network connection established to {conn_info}")
                                        
                                        # Check if connection is suspicious
                                        if is_network_connection_suspicious(conn.raddr) and conn_info not in suspicious_connections:
                                            suspicious_connections.add(conn_info)
                                            threat_score += 4
                                            record_event("SUSPICIOUS_CONNECTION", 
                                                      f"SUSPICIOUS network connection detected to {conn_info}", 
                                                      "WARNING")
                                            threat_indicators.append(f"Suspicious network connection: {conn_info}")
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        # Monitor child processes
                        try:
                            children = proc.children(recursive=True)
                            for child in children:
                                try:
                                    child_info = f"{child.name()} (PID: {child.pid})"
                                    if child_info not in child_processes:
                                        child_processes.add(child_info)
                                        threat_score += 3
                                        record_event("CHILD_PROCESS", f"Child process created: {child_info}", "WARNING")
                                        threat_indicators.append(f"Created child process: {child_info}")
                                except (psutil.AccessDenied, psutil.NoSuchProcess):
                                    pass
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                            
                        # Check for self-deletion attempts
                        if not os.path.exists(executable_path) and not termination_triggered:
                            threat_score += 10
                            record_event("SELF_DELETION", 
                                       "CRITICAL: Malware attempted to delete itself (anti-analysis technique)", 
                                       "CRITICAL")
                            threat_indicators.append("Self-deletion attempt")
                            termination_triggered = True
                        
                        # Terminate process if threat score is too high or critical violations detected
                        if (threat_score >= 15 or termination_triggered) and sandbox_mode:
                            reason = "high threat score" if threat_score >= 15 else "critical violation"
                            record_event("PROTECTION_TRIGGERED", 
                                       f"SECURITY ALERT: Terminating process due to {reason} ({threat_score})", 
                                       "CRITICAL")
                            
                            try:
                                logger.critical("[!!!] SECURITY PROTECTION TRIGGERED - TERMINATING MALICIOUS PROCESS")
                                
                                # Kill the process tree
                                parent = psutil.Process(pid)
                                children = parent.children(recursive=True)
                                for child in children:
                                    try:
                                        child.kill()
                                    except:
                                        pass
                                parent.kill()
                                
                                process_active = False
                                logger.info("[+] Process terminated successfully for security reasons")
                            except Exception as e:
                                logger.error(f"[-] Failed to terminate process: {e}")
                    
                    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                        logger.warning(f"[-] Lost access to process: {e}")
                        if not psutil.pid_exists(pid):
                            process_active = False
                            record_event("PROCESS_EXIT", "Process terminated on its own")
                else:
                    if process_active and not psutil.pid_exists(pid):
                        process_active = False
                        record_event("PROCESS_EXIT", "Process terminated on its own")
                
                # Sleep briefly between checks
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            logger.info("\n[+] Monitoring stopped by user")
            record_event("USER_INTERRUPT", "Monitoring stopped by user")
        
        # Ensure process is terminated
        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                logger.info("[+] Cleaning up: terminating process...")
                
                # Kill process tree
                children = proc.children(recursive=True)
                for child in children:
                    try:
                        child.kill()
                    except:
                        pass
                proc.kill()
                
                logger.info("[+] Process terminated")
            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                logger.warning(f"[-] Could not terminate process: {e}")
        
        # Check if the executable's hash has changed
        try:
            if os.path.exists(executable_path):
                final_hash = calculate_file_hash(executable_path)
                if final_hash != initial_hash:
                    threat_score += 8
                    logger.critical(f"[!!!] CRITICAL: Executable hash changed from {initial_hash} to {final_hash}")
                    threat_indicators.append("Executable self-modification")
                else:
                    logger.info(f"[+] Executable hash remained unchanged: {final_hash}")
            else:
                logger.critical("[!!!] CRITICAL: Executable has been deleted during execution")
                threat_indicators.append("Executable self-deletion")
                threat_score += 8
        except Exception as e:
            logger.error(f"[-] Error calculating final hash: {e}")
        
        # Generate threat assessment
        threat_level = "LOW"
        if threat_score >= 20:
            threat_level = "CRITICAL"
        elif threat_score >= 10:
            threat_level = "HIGH"
        elif threat_score >= 5:
            threat_level = "MEDIUM"
        
        # Analysis summary
        analysis_duration = time.time() - start_time
        logger.info("\n" + "="*80)
        logger.info("MALWARE ANALYSIS SUMMARY")
        logger.info("="*80)
        logger.info(f"Analysis completed in {analysis_duration:.2f} seconds")
        logger.info(f"Sample: {os.path.basename(executable_path)}")
        logger.info(f"SHA256: {initial_hash}")
        logger.info(f"Threat assessment: {threat_level} (Score: {threat_score})")
        
        if threat_indicators:
            logger.info("\nThreat indicators detected:")
            for i, indicator in enumerate(threat_indicators, 1):
                logger.info(f"  {i}. {indicator}")
        
        logger.info("\nActivity statistics:")
        logger.info(f"  Total files accessed: {len(accessed_files)}")
        logger.info(f"  Suspicious files accessed: {len(suspicious_files_accessed)}")
        logger.info(f"  Files modified: {len(modified_files)}")
        logger.info(f"  Suspicious files modified: {len(suspicious_files_modified)}")
        logger.info(f"  Network connections: {len(network_connections)}")
        logger.info(f"  Suspicious network connections: {len(suspicious_connections)}")
        logger.info(f"  Child processes spawned: {len(child_processes)}")
        
        # Detailed logs section
        if suspicious_files_accessed:
            logger.info("\nSuspicious files accessed:")
            for file in sorted(suspicious_files_accessed):
                logger.info(f"  - {file}")
        
        if suspicious_files_modified:
            logger.info("\nSuspicious files modified:")
            for file in sorted(suspicious_files_modified):
                logger.info(f"  - {file}")
        
        if suspicious_connections:
            logger.info("\nSuspicious network connections:")
            for conn in sorted(suspicious_connections):
                logger.info(f"  - {conn}")
        
        if child_processes:
            logger.info("\nChild processes:")
            for proc in sorted(child_processes):
                logger.info(f"  - {proc}")
        
        logger.info("\nAnalysis log saved to:")
        logger.info(f"  {log_file}")
        logger.info("="*80)
        
        return {
            "threat_score": threat_score,
            "threat_level": threat_level,
            "threat_indicators": threat_indicators,
            "analysis_duration": analysis_duration,
            "log_file": log_file
        }
        
    except Exception as e:
        logger.error(f"[-] Error during malware monitoring: {e}")
        return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Malware Behavior Monitoring Tool")
    parser.add_argument("--target", "-t", required=True,
                      help="Path to the suspicious executable to monitor")
    parser.add_argument("--time", "-m", type=int, default=60,
                      help="Minimum monitoring time in seconds")
    parser.add_argument("--sandbox", "-s", action="store_true",
                      help="Enable sandbox protection mode (terminates process if dangerous activity detected)")
    parser.add_argument("--no-sandbox", action="store_true",
                      help="Disable sandbox protection (observe all activity without interference)")
    
    args = parser.parse_args()
    
    # Print banner
    # print(f"""
    # ╔═══════════════════════════════════════════════════════╗
    # ║  ENHANCED MALWARE ACTIVITY MONITOR                    ║
    # ║  -----------------------------------                   ║
    # ║  WARNING: Only run suspicious files in isolated        ║
    # ║           environments like a VM or sandbox!           ║
    # ╚═══════════════════════════════════════════════════════╝
    # """)
    
    if args.no_sandbox:
        sandbox_mode = False
    else:
        sandbox_mode = True
    
    if os.path.exists(args.target):
        logger.info(f"[+] Starting analysis of: {args.target}")
        monitor_process_activity(args.target, args.time, sandbox_mode)
    else:
        logger.error(f"[-] File not found: {args.target}")
        sys.exit(1)



        # python .\dynamic_analysis.py --target C:\Users\john\Desktop\network_analysis_dashboard\uploads\Code.exe