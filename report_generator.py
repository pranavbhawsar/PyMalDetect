import os
from jinja2 import Template

def generate_html_report(full_report, output_path="output/report.html"):
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Malware Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            h1, h2 { color: #333; }
            pre { background-color: #f4f4f4; padding: 10px; border: 1px solid #ccc; }
            .risk-bar {
                width: 300px;
                height: 25px;
                background-color: #eee;
                border: 1px solid #ccc;
                margin: 10px 0;
            }
            .risk-fill {
                height: 100%;
                text-align: center;
                color: white;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Malware Analysis Report</h1>

        <h2>Risk Assessment</h2>
        <p><strong>Score:</strong> {{ risk.score }}</p>
        <p><strong>Verdict:</strong> {{ risk.verdict }}</p>
        <div class="risk-bar">
            <div class="risk-fill" style="width: {{ risk.score * 15 }}%; background-color:
                {% if risk.verdict == 'High' %}#e74c3c
                {% elif risk.verdict == 'Medium' %}#f39c12
                {% else %}#2ecc71
                {% endif %};">
                {{ risk.verdict }}
            </div>
        </div>

        <h2>Reasons</h2>
        <ul>
            {% for reason in risk.reasons %}
            <li>{{ reason }}</li>
            {% endfor %}
        </ul>

        <h2>Static Analysis</h2>
        <pre>{{ static_analysis | tojson(indent=4) }}</pre>

        <h2>Dynamic Analysis</h2>
        <pre>{{ dynamic_analysis | tojson(indent=4) }}</pre>
    </body>
    </html>
    """

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    template = Template(html_template)
    risk = full_report.get("dynamic_analysis", {}).get("risk_assessment", {})

    rendered_html = template.render(
        static_analysis=full_report.get("static_analysis", {}),
        dynamic_analysis=full_report.get("dynamic_analysis", {}),
        risk=risk
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"[+] HTML report generated at {output_path}")
