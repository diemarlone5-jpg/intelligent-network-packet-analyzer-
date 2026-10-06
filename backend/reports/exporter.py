import io
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_csv_report(packets_data):
    if not packets_data:
        return b""
    df = pd.DataFrame(packets_data)
    return df.to_csv(index=False).encode('utf-8')

def generate_pdf_report(packets_data, alerts_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Titre
    story.append(Paragraph("<b>Rapport d'Analyse Réseau</b>", styles['Title']))
    story.append(Spacer(1, 12))

    # Résumé
    total_packets = len(packets_data)
    total_alerts = len(alerts_data)
    summary_text = f"<b>Paquets capturés :</b> {total_packets} | <b>Alertes détectées :</b> {total_alerts}"
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 18))

    # Section Alertes
    story.append(Paragraph("<b>Alertes de Sécurité</b>", styles['Heading2']))
    if alerts_data:
        alert_rows = [["Horodatage", "Source", "Destination", "Type"]]
        for a in alerts_data:
            a_info = a.get("alerts", [{}])[0]
            alert_rows.append([
                str(a.get("timestamp", "N/A"))[:19],
                str(a.get("src_ip", "N/A")),
                str(a.get("dst_ip", "N/A")),
                str(a_info.get("type", "N/A"))
            ])
        t_alerts = Table(alert_rows, colWidths=[130, 120, 120, 110])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#D32F2F")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(t_alerts)
    else:
        story.append(Paragraph("Aucune anomalie détectée.", styles['Normal']))

    story.append(Spacer(1, 18))

    # Section Paquets Récents
    story.append(Paragraph("<b>Derniers Paquets Capturés</b>", styles['Heading2']))
    if packets_data:
        p_rows = [["Proto", "Source", "Pays", "Org", "Taille"]]
        for p in packets_data[-10:]:
            p_rows.append([
                str(p.get("protocol", "N/A")),
                str(p.get("src_ip", "N/A"))[:20],
                str(p.get("country", "N/A")),
                str(p.get("org", "N/A"))[:20],
                str(p.get("length", 0))
            ])
        t_packets = Table(p_rows, colWidths=[50, 140, 60, 180, 50])
        t_packets.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1976D2")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8),
        ]))
        story.append(t_packets)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
