#!/usr/bin/env python3
"""
HTML Compliance Reporter
========================
Generates a beautiful, executive-ready HTML report from compliance snapshots.
Designed to be printed to PDF.
"""

import json
import os
from datetime import datetime
from pathlib import Path
import sys

# Template for the HTML Report
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Compliance Report - {date}</title>
    <style>
        :root {{
            --primary: #2563eb;
            --success: #16a34a;
            --warning: #ca8a04;
            --danger: #dc2626;
            --gray: #6b7280;
            --light: #f3f4f6;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            color: #1f2937;
            max-width: 210mm; /* A4 width */
            margin: 0 auto;
            padding: 2rem;
            background: #fff;
        }}

        @media print {{
            body {{ padding: 0; }}
            .no-print {{ display: none; }}
        }}

        header {{
            border-bottom: 2px solid var(--primary);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}

        h1 {{ margin: 0; font-size: 24px; color: var(--primary); }}
        h2 {{ font-size: 18px; border-left: 4px solid var(--primary); padding-left: 10px; margin-top: 2rem; }}
        
        .meta {{ font-size: 0.9rem; color: var(--gray); text-align: right; }}

        /* Summary Cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--light);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        .card .value {{ font-size: 2rem; font-weight: bold; }}
        .card .label {{ font-size: 0.8rem; color: var(--gray); text-transform: uppercase; }}
        
        .score-box {{ background: #eff6ff; border: 1px solid #bfdbfe; }}
        .pass-box {{ color: var(--success); }}
        .fail-box {{ color: var(--danger); }}

        /* Progress Bars */
        .bar-container {{
            margin-bottom: 0.5rem;
        }}
        .bar-label {{ display: flex; justify-content: space-between; font-size: 0.9rem; margin-bottom: 2px; }}
        .progress {{
            height: 10px;
            background: #e5e7eb;
            border-radius: 5px;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 5px;
            transition: width 0.3s ease;
        }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
        th {{ text-align: left; background: var(--light); padding: 0.5rem; border-bottom: 2px solid #e5e7eb; }}
        td {{ padding: 0.5rem; border-bottom: 1px solid #e5e7eb; }}
        tr:last-child td {{ border-bottom: none; }}
        
        .badge {{
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .badge-pass {{ background: #dcfce7; color: #166534; }}
        .badge-fail {{ background: #fee2e2; color: #991b1b; }}
        .badge-critical {{ background: #7f1d1d; color: white; }}
        .badge-high {{ background: #ef4444; color: white; }}
        .badge-medium {{ background: #f59e0b; color: white; }}
        
        footer {{
            margin-top: 4rem;
            border-top: 1px solid #e5e7eb;
            padding-top: 1rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--gray);
        }}
    </style>
</head>
<body>

    <header>
        <div>
            <h1>OpenStack Compliance Report</h1>
            <div style="margin-top: 5px; font-weight: bold;">CIS Benchmark Level 1</div>
        </div>
        <div class="meta">
            <div><strong>Report ID:</strong> {report_id}</div>
            <div><strong>Generated:</strong> {generated_at}</div>
        </div>
    </header>

    <div class="summary-grid">
        <div class="card score-box">
            <div class="value" style="color: {score_color}">{score}%</div>
            <div class="label">Compliance Score</div>
        </div>
        <div class="card">
            <div class="value">{total_controls}</div>
            <div class="label">Controls Checked</div>
        </div>
        <div class="card">
            <div class="value pass-box">{passed}</div>
            <div class="label">Passed</div>
        </div>
        <div class="card">
            <div class="value fail-box">{failed}</div>
            <div class="label">Failed</div>
        </div>
    </div>

    <h2>⚠️ Compliance by Severity</h2>
    {severity_bars}

    <h2>📊 Compliance by Section</h2>
    {section_bars}

    <h2>🚫 Top Violations</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            {top_violations_rows}
        </tbody>
    </table>

    <footer>
        Generated by Compliance-as-Code Framework | Confidential Internal Document
    </footer>

    <script>
        window.onload = function() {{
            // Auto-print prompt if preferred
            // window.print();
        }}
    </script>
</body>
</html>
"""

class HTMLReporter:
    def __init__(self, evidence_dir):
        self.evidence_dir = Path(evidence_dir)

    def get_latest_snapshot(self):
        """Find the most recent daily snapshot in the evidence store"""
        try:
            # Walk through directories to find snapshots
            snapshot_dir = self.evidence_dir / "snapshots" / "daily"
            if not snapshot_dir.exists():
                return None
            
            # Find all json files recursively
            files = sorted(snapshot_dir.glob("**/*.json"), key=os.path.getmtime, reverse=True)
            if not files:
                return None
                
            with open(files[0], 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading snapshot: {e}")
            return None

    def generate_bar(self, label, percentage, color_class="primary"):
        """Generate HTML for a progress bar"""
        color = "#2563eb" # Default Blue
        if percentage >= 90: color = "#16a34a" # Green
        elif percentage >= 70: color = "#ca8a04" # Yellow
        else: color = "#dc2626" # Red

        return f"""
        <div class="bar-container">
            <div class="bar-label">
                <span>{label}</span>
                <strong>{percentage}%</strong>
            </div>
            <div class="progress">
                <div class="progress-fill" style="width: {percentage}%; background-color: {color};"></div>
            </div>
        </div>
        """

    def generate(self, output_path):
        snapshot = self.get_latest_snapshot()
        if not snapshot:
            print("❌ No compliance snapshots found. Run a scan first!")
            return False

        # Extract data
        overall = snapshot.get('overall', {})
        score = overall.get('compliance_score', 0)
        
        # Determine score color
        score_color = "#2563eb"
        if score >= 90: score_color = "#16a34a"
        elif score < 70: score_color = "#dc2626"

        # Severity Bars
        severity_html = ""
        severities = snapshot.get('by_severity', {})
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            data = severities.get(severity, {})
            pct = data.get('compliance_percentage', 0)
            severity_html += self.generate_bar(severity, pct)

        # Section Bars
        section_html = ""
        sections = snapshot.get('by_section', {})
        for section_name, data in sections.items():
            pct = data.get('compliance_percentage', 0)
            section_html += self.generate_bar(section_name, pct)

        # Violations Table
        violations_html = ""
        for v in snapshot.get('top_violations', []):
            sev_class = f"badge-{v['severity'].lower()}"
            violations_html += f"""
            <tr>
                <td><code>{v['control_id']}</code></td>
                <td>{v['title']}</td>
                <td><span class="badge {sev_class}">{v['severity']}</span></td>
                <td>{v['affected_resources']}</td>
            </tr>
            """

        # Fill Template
        html_content = HTML_TEMPLATE.format(
            date=datetime.now().strftime("%Y-%m-%d"),
            report_id=snapshot.get('snapshot_id', 'unknown'),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score=score,
            score_color=score_color,
            total_controls=overall.get('total_controls', 0),
            passed=overall.get('controls_passed', 0),
            failed=overall.get('controls_failed', 0),
            severity_bars=severity_html,
            section_bars=section_html,
            top_violations_rows=violations_html
        )

        with open(output_path, 'w') as f:
            f.write(html_content)
            
        print(f"✅ Report generated: {output_path}")
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="compliance-report.html")
    parser.add_argument("--evidence-dir", default="evidence_store")
    args = parser.parse_args()

    reporter = HTMLReporter(args.evidence_dir)
    reporter.generate(args.out)

if __name__ == "__main__":
    main()
