# nis2_scanner.py

import json
import platform
import subprocess
import socket
from datetime import datetime

# psutil is an external library, it needs to be installed: pip install psutil
try:
    import psutil
except ImportError:
    print("Error: 'psutil' library is not installed. Please run 'pip install psutil'")
    exit()

# winreg is only needed for Windows
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        # This module should be available in standard Python installations on Windows
        print("Error: Failed to import 'winreg'. The script might not function correctly on Windows.")

class Nis2ComplianceScanner:
    """
    A cross-platform scanner for collecting basic system information
    in the context of the NIS2 directive requirements.
    """

    def __init__(self):
        self.os_type = platform.system()
        self.report = {}

    def get_system_info(self):
        """Gathers basic information about the operating system."""
        return {
            "os_type": self.os_type,
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
        }

    def get_installed_software_linux(self):
        """Gets the list of installed software for Debian/RPM-based Linux."""
        packages = []
        # Attempt for Debian-based systems (Ubuntu, Debian)
        try:
            # Command to get the list of packages in "name version" format
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}\t${Version}\n'],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    name, version = line.split('\t')
                    packages.append({"name": name, "version": version})
            return packages
        except (subprocess.CalledProcessError, FileNotFoundError):
            # If dpkg is not found, try for RPM-based systems (CentOS, Fedora)
            try:
                result = subprocess.run(
                    ['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n'],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        name, version = line.split('\t')
                        packages.append({"name": name, "version": version})
                return packages
            except (subprocess.CalledProcessError, FileNotFoundError):
                return [{"error": "Could not determine the package manager (neither dpkg nor rpm)"}]

    def get_installed_software_windows(self):
        """Gets the list of installed software for Windows from the registry."""
        packages = []
        # Registry paths where information about installed programs is stored
        uninstall_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" # for 32-bit applications on a 64-bit OS
        ]
        for path in uninstall_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        packages.append({"name": name, "version": str(version)})
                    except OSError:
                        # Not all subkeys have these values, which is normal
                        pass
                    finally:
                        subkey.Close()
            except OSError:
                # This path may not exist, which is also normal
                pass
        # Removing potential duplicates
        unique_packages = [dict(t) for t in {tuple(d.items()) for d in packages}]
        return unique_packages

    def get_network_info(self):
        """Gathers information about open ports and the services listening on them."""
        listening_connections = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'LISTEN':
                    proc_name = "N/A"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except psutil.NoSuchProcess:
                            # The process could have terminated between calls
                            proc_name = "Process terminated"
                    listening_connections.append({
                        "port": conn.laddr.port,
                        "address": conn.laddr.ip,
                        "protocol": "TCP" if conn.type.name == 'SOCK_STREAM' else "UDP",
                        "process_name": proc_name
                    })
        except Exception as e:
            return [{"error": f"Error getting network information: {e}"}]
        return listening_connections

    def run_scan(self):
        """Runs all checks and builds the final report."""
        print("Starting system scan...")

        # Asset inventory - the foundation for risk management
        print("1. Gathering system information and software list (SBOM)...")
        if self.os_type == "Linux":
            software_list = self.get_installed_software_linux()
        elif self.os_type == "Windows":
            software_list = self.get_installed_software_windows()
        else:
            software_list = [{"error": f"Operating system {self.os_type} is not supported"}]

        asset_management_data = {
            "system_info": self.get_system_info(),
            "installed_software_sbom": software_list,
        }

        # Basic security analysis - open ports
        print("2. Analyzing network connections...")
        network_data = self.get_network_info()

        # Building the report, linked to NIS2
        self.report = {
            "scan_metadata": {
                "scan_time_utc": datetime.utcnow().isoformat(),
                "scanner_version": "0.1.0"
            },
            "nis2_compliance_checks": {
                "article_21_asset_management": {
                    "title": "Asset and Software Inventory (SBOM)",
                    "status": "COMPLETED",
                    "data": asset_management_data
                },
                "article_21_system_security": {
                    "title": "Basic System Security Analysis (Open Ports)",
                    "status": "COMPLETED",
                    "data": {
                        "listening_ports": network_data
                    }
                }
            }
        }
        print("Scan complete.")
        return self.report

# --- Program entry point ---
if __name__ == "__main__":
    scanner = Nis2ComplianceScanner()
    scan_result = scanner.run_scan()

    # Print the result to the console in a readable JSON format
    print("\n--- SCAN RESULTS (JSON format) ---")
    print(json.dumps(scan_result, indent=4))

    # Save the report to a file
    file_name = f"nis2_report_{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(file_name, 'w', encoding='utf-8') as f:
        json.dump(scan_result, f, indent=4)
    
    print(f"\nReport saved to file: {file_name}")