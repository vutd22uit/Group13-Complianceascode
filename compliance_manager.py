#!/usr/bin/env python3
"""
Compliance Manager CLI
======================
The unified command-line interface for the Compliance-as-Code Framework.
Use this tool to manage scans, remediation, and reporting.

Usage:
    ./compliance_manager.py [command] [options]

Commands:
    scan        Run compliance scans (InSpec)
    remediate   Apply remediation playbooks (Ansible)
    report      Generate compliance reports (HTML/PDF)
    dashboard   Start/Stop the monitoring dashboard
    init        Initialize the environment
"""

import argparse
import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent.absolute()
EVIDENCE_DIR = PROJECT_ROOT / "evidence_store"
SCAN_RESULTS_DIR = PROJECT_ROOT / "scan-results"

def run_command(cmd, cwd=None, env=None):
    """Run a shell command and stream output"""
    print(f"🚀 Running: {' '.join(cmd)}")
    try:
        process = subprocess.Popen(
            cmd, 
            cwd=cwd or PROJECT_ROOT,
            env=env or os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Stream output
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(f"  {output.strip()}")
                
        return process.returncode
    except Exception as e:
        print(f"❌ Error executing command: {e}")
        return 1

def cmd_scan(args):
    """Execute InSpec scans"""
    print(f"🔍 Starting {args.target} compliance scan...")
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = SCAN_RESULTS_DIR / f"scan-{args.target}-{timestamp}.json"
    SCAN_RESULTS_DIR.mkdir(exist_ok=True)
    
    target_path = ""
    if args.target == 'openstack':
        target_path = "tests/inspec/openstack-cis"
    elif args.target == 'linux':
        target_path = "tests/inspec/linux-cis"
    else:
        print(f"❌ Unknown target: {args.target}")
        return

    # Construct InSpec command
    cmd = [
        "inspec", "exec", target_path,
        "--reporter", f"cli", f"json:{str(output_file)}",
        "--chef-license", "accept-silent"
    ]
    
    if args.backend == 'ssh':
        if not args.host:
            print("❌ --host required for SSH backend")
            return
        cmd.extend(["-t", f"ssh://{args.user}@{args.host}"])
        if args.key:
            cmd.extend(["-i", args.key])
    elif args.backend == 'docker':
        if not args.container:
            print("❌ --container required for Docker backend")
            return
        cmd.extend(["-t", f"docker://{args.container}"])
    
    if run_command(cmd) == 0:
        print(f"\n✅ Scan complete! Results saved to:\n  {output_file}")
        
        # Auto-process evidence
        print("\n📦 Processing evidence...")
        processor_cmd = [
            "python3", "evidence/collectors/evidence_collector.py",
            "--inspec-json", str(output_file),
            "--store"
        ]
        run_command(processor_cmd)
    else:
        print("\n❌ Scan failed!")

def cmd_report(args):
    """Generate reports"""
    print("📊 Generating Compliance Report...")
    
    if args.format == 'html':
        output_path = PROJECT_ROOT / f"compliance-report-{datetime.now().strftime('%Y%m%d')}.html"
        cmd = [
            "python3", "evidence/reporters/html_reporter.py",
            "--out", str(output_path),
            "--evidence-dir", str(EVIDENCE_DIR)
        ]
        if run_command(cmd) == 0:
            print(f"\n✅ Report Ready: {output_path}")
            print(f"   (Open this file in your browser window to view or print to PDF)")
            try:
                # Try to open automatically (Mac)
                subprocess.run(["open", str(output_path)], check=False)
            except:
                pass
    else:
        print(f"⚠️  Format {args.format} not heavily supported yet. generating via legacy reporter...")
        cmd = [
            "python3", "evidence/reporters/compliance_reporter.py", 
            "--bucket", "local-evidence-store", 
            "--type", "daily",
            "--format", args.format
        ]
        run_command(cmd)

def cmd_dashboard(args):
    """Manage dashboard"""
    compose_file = PROJECT_ROOT / "dashboards" / "docker-compose.yml"
    
    if args.action == 'start':
        print("📈 Starting Monitoring Stack (Grafana + Prometheus)...")
        run_command(["docker-compose", "-f", str(compose_file), "up", "-d"])
        print("\n✅ Dashboard available at http://localhost:3000 (admin/openstack-cis-2024)")
    elif args.action == 'stop':
        print("🛑 Stopping Monitoring Stack...")
        run_command(["docker-compose", "-f", str(compose_file), "down"])

def cmd_remediate(args):
    """Run remediation"""
    print(f"🛠 Applying remediation for {args.target}...")
    
    playbook = ""
    if args.target == 'openstack':
        playbook = "remediation/ansible/cis-openstack-remediation.yml"
    elif args.target == 'linux':
        playbook = "remediation/ansible/cis-linux-remediation.yml"
        
    cmd = ["ansible-playbook", playbook]
    
    if args.inventory:
        cmd.extend(["-i", args.inventory])
    
    if args.dry_run:
        cmd.append("--check")
        
    run_command(cmd)

def main():
    parser = argparse.ArgumentParser(description="Compliance-as-Code Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # scan
    parser_scan = subparsers.add_parser("scan", help="Run compliance scan")
    parser_scan.add_argument("--target", choices=['openstack', 'linux'], required=True)
    parser_scan.add_argument("--backend", choices=['local', 'ssh', 'docker'], default='local')
    parser_scan.add_argument("--host", help="Target host (for ssh)")
    parser_scan.add_argument("--user", default="root", help="SSH user")
    parser_scan.add_argument("--key", help="SSH key path")
    parser_scan.add_argument("--container", help="Container ID (for docker)")
    
    # report
    parser_report = subparsers.add_parser("report", help="Generate report")
    parser_report.add_argument("--format", choices=['html', 'pdf', 'markdown'], default='html')
    
    # dashboard
    parser_dash = subparsers.add_parser("dashboard", help="Manage dashboard")
    parser_dash.add_argument("action", choices=['start', 'stop', 'restart'])
    
    # remediate
    parser_rem = subparsers.add_parser("remediate", help="Apply fixes")
    parser_rem.add_argument("--target", choices=['openstack', 'linux'], required=True)
    parser_rem.add_argument("--inventory", help="Ansible inventory file")
    parser_rem.add_argument("--dry-run", action="store_true", help="Don't make changes")

    args = parser.parse_args()
    
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "remediate":
        cmd_remediate(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
