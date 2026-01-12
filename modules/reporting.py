from jinja2 import Environment, BaseLoader
import os
from datetime import datetime

# Updated Report Generator for Specialist Audit Findings
class ReportGenerator:
    def __init__(self):
        self.template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubEnum Report - {{ domain }}</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --text-color: #c9d1d9;
            --accent-color: #58a6ff;
            --border-color: #30363d;
            --header-bg: #161b22;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            background-color: var(--header-bg);
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            border-radius: 6px 6px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 { margin: 0; color: var(--accent-color); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background-color: var(--header-bg);
            padding: 20px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            text-align: center;
        }
        .stat-value { font-size: 2em; font-weight: bold; color: white; }
        .stat-label { color: #8b949e; }
        
        .section {
            background-color: var(--header-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }
        h2 { border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-top: 0; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }
        th { color: var(--accent-color); }
        tr:hover { background-color: #21262d; }
        
        .tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 4px;
        }
        .tag-port { background-color: #238636; color: white; }
        .tag-ips { background-color: #1f6feb; color: white; }
        .tag-tech { background-color: #8957e5; color: white; }
        
        .tag-vuln { background-color: #da3633; color: white; animation: pulse 2s infinite; }
        .tag-crit { background-color: #b31d28; color: white; animation: pulse 1s infinite; font-weight: 900; border: 1px solid white; }
        
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.7; } 100% { opacity: 1; } }
        
        pre {
            background-color: #000;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            color: #7ee787;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>SubEnum Report - Specialist Audit</h1>
                <p>Target: <strong>{{ domain }}</strong></p>
            </div>
            <div style="text-align: right;">
                <p>Generated: {{ timestamp }}</p>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ results|length }}</div>
                <div class="stat-label">Assets Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ unique_ips }}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ open_ports_total }}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card" style="border-color: #da3633;">
                <div class="stat-value" style="color: #da3633;">{{ vuln_count }}</div>
                <div class="stat-label">Vulnerabilities Detected</div>
            </div>
        </div>

        {% if ai_report %}
        <div class="section">
            <h2>🤖 AI Security Analysis</h2>
            <div style="white-space: pre-wrap; font-family: sans-serif;">{{ ai_report }}</div>
        </div>
        {% endif %}

        <div class="section">
            <h2>Discovered Assets</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 20%;">Subdomain</th>
                        <th style="width: 15%;">IP / CNAME</th>
                        <th style="width: 10%;">Ports</th>
                        <th style="width: 20%;">Technologies</th>
                        <th style="width: 35%;">Security Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in results %}
                    <tr>
                        <td>
                            <strong>{{ r.subdomain }}</strong>
                        </td>
                        <td>
                            {% for ip in r.ip_addresses %}
                            <div class="tag tag-ips">{{ ip }}</div><br>
                            {% endfor %}
                            <div style="color: #e3b341; font-size: 0.9em; margin-top:5px;">{{ r.cname }}</div>
                        </td>
                        <td>
                            {% if r.open_ports %}
                                {% for port in r.open_ports %}
                                <span class="tag tag-port">{{ port }}</span>
                                {% endfor %}
                            {% else %}
                                <span style="color: #8b949e">-</span>
                            {% endif %}
                        </td>
                        <td>
                             {% if r.technologies %}
                                {% for k, v in r.technologies.items() %}
                                <div class="tag tag-tech">{{ k }}: {{ v }}</div>
                                {% endfor %}
                            {% else %}
                                <span style="color: #8b949e">-</span>
                            {% endif %}
                        </td>
                         <td>
                            {% if r.takeover %}
                                <div class="tag tag-crit">⚠ SUBDOMAIN TAKEOVER: {{ r.takeover }}</div><br>
                            {% endif %}
                            
                            {% if r.sensitive_files %}
                                {% for file in r.sensitive_files %}
                                <div class="tag tag-vuln">Exposed: {{ file }}</div><br>
                                {% endfor %}
                            {% endif %}
                            
                            {% if r.vulnerabilities %}
                                {% for vuln in r.vulnerabilities %}
                                <div class="tag tag-vuln">{{ vuln }}</div><br>
                                {% endfor %}
                            {% endif %}

                            {% if r.js_secrets %}
                                {% for secret in r.js_secrets %}
                                <div class="tag tag-vuln" style="background-color: #f778ba;">🔑 JS Secret: {{ secret }}</div><br>
                                {% endfor %}
                            {% endif %}
                            
                            {% if not r.takeover and not r.sensitive_files and not r.vulnerabilities and not r.js_secrets %}
                                <span style="color: #238636;">Safe</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

    def generate(self, domain: str, results: list, ai_report: str = ""):
        env = Environment(loader=BaseLoader())
        template = env.from_string(self.template_str)
        
        # Calculate stats
        all_ips = set()
        open_ports_total = 0
        vuln_count = 0
        
        for r in results:
            for ip in r.get('ip_addresses', []):
                all_ips.add(ip)
            if r.get('open_ports'):
                open_ports_total += len(r['open_ports'])
            
            # Count vulns + sensitive files + takeovers
            if r.get('vulnerabilities'):
                vuln_count += len(r['vulnerabilities'])
            if r.get('sensitive_files'):
                vuln_count += len(r['sensitive_files'])
            if r.get('takeover'):
                vuln_count += 1

        html = template.render(
            domain=domain,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results=results,
            unique_ips=len(all_ips),
            open_ports_total=open_ports_total,
            vuln_count=vuln_count,
            ai_report=ai_report
        )
        
        filename = f"report_{domain}.html"
        with open(filename, "w") as f:
            f.write(html)
        
        return filename
