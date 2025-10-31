# core/pdf_generator.py
from weasyprint import HTML
from datetime import datetime

def generate_executive_report(results, output_path):
    total_hosts = len(results)
    vulns = []
    for host in results:
        for v in host.get('vulns', []):
            vulns.append({**v, 'ip': host['ip']})
    
    critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
    high = len([v for v in vulns if v.get('severity') == 'HIGH'])
    
    # Generar filas de la tabla
    rows = ""
    for v in vulns:
        color = "#e74c3c" if v['severity'] == "CRITICAL" else "#f39c12" if v['severity'] == "HIGH" else "#3498db"
        rows += f"""
        <tr>
            <td>{v['ip']}</td>
            <td>{v['id']}</td>
            <td style="color:{color}; font-weight:bold;">{v['severity']}</td>
            <td>{v.get('cvss', 'N/A')}</td>
            <td>{v['description']}</td>
        </tr>"""
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f8f9fa; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
            .metric {{ font-size: 28px; font-weight: bold; color: #3498db; }}
            .critical {{ color: #e74c3c !important; }}
            .high {{ color: #f39c12 !important; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-top: 20px; }}
            th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid #eee; }}
            th {{ background: #34495e; color: white; font-weight: 600; }}
            tr:hover {{ background-color: #f5f7fa; }}
            .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; padding: 20px; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>pentscan</h1>
                <p>Reporte de Seguridad Ofensiva - {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
            </div>
            
            <div class="summary-grid">
                <div class="card">
                    <div class="metric">{total_hosts}</div>
                    <div>Hosts Analizados</div>
                </div>
                <div class="card">
                    <div class="metric">{len(vulns)}</div>
                    <div>Vulnerabilidades</div>
                </div>
                <div class="card">
                    <div class="metric critical">{critical}</div>
                    <div>Críticas</div>
                </div>
                <div class="card">
                    <div class="metric high">{high}</div>
                    <div>Altas</div>
                </div>
            </div>
            
            <h2 style="color: #2c3e50; margin-top: 40px;">Hallazgos Detallados</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>ID</th>
                        <th>Severidad</th>
                        <th>CVSS</th>
                        <th>Descripción</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else "<tr><td colspan='5' style='text-align:center;padding:30px;'>No se encontraron vulnerabilidades.</td></tr>"}
                </tbody>
            </table>
            
            <div class="footer">
                <p>Generado con pentscan • Herramienta de Pentesting Profesional</p>
                <p>Confidencial - Solo para uso autorizado</p>
            </div>
        </div>
    </body>
    </html>"""
    
    HTML(string=html).write_pdf(output_path)