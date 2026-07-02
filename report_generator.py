"""Generazione di report PDF sull'inventario di rete (reportlab, nessuna
dipendenza da binari esterni come wkhtmltopdf). Due sezioni componibili:

- 'summary': stat box, distribuzione tipo dispositivo (grafico a barre),
  top vulnerabilità per CVSS, esposizione MITRE ATT&CK per tattica
- 'hosts': tabella completa di tutti gli host (IP, tipo, OS, porte, vuln)

Uso:
    from report_generator import generate_report_pdf
    pdf_bytes = generate_report_pdf(conn, kinds=("summary", "hosts"))
"""

import datetime
import io

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import scanner_db

STYLES = getSampleStyleSheet()
TITLE_STYLE = ParagraphStyle("ReportTitle", parent=STYLES["Title"], fontSize=20, spaceAfter=6)
SUBTITLE_STYLE = ParagraphStyle("ReportSubtitle", parent=STYLES["Normal"], fontSize=10, textColor=colors.grey)
H2_STYLE = ParagraphStyle("H2", parent=STYLES["Heading2"], spaceBefore=14, spaceAfter=6)
BODY_STYLE = STYLES["Normal"]

HEADER_BG = colors.HexColor("#495057")
STRIPE_BG = colors.HexColor("#f2f2f2")
DEVICE_PALETTE = [
    colors.HexColor(c) for c in
    ["#4e79a7", "#76b7b2", "#e15759", "#59a14f", "#9c755f", "#af7aa1",
     "#f28e2b", "#b6992d", "#ff9da7", "#ffbe7d"]
]


def _table_style(header_bg=HEADER_BG, stripe=True):
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if stripe:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, STRIPE_BG]))
    return TableStyle(style)


def _stat_boxes(conn):
    total_hosts = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
    total_services = conn.execute("SELECT COUNT(*) c FROM services WHERE state='open'").fetchone()["c"]
    device_types = conn.execute(
        "SELECT COUNT(DISTINCT COALESCE(device_type,'unknown')) c FROM hosts"
    ).fetchone()["c"]
    scans_total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    hosts_exposed = conn.execute(
        "SELECT COUNT(DISTINCT host_id) c FROM host_attack_techniques"
    ).fetchone()["c"]
    vuln_total = conn.execute("SELECT COUNT(*) c FROM host_vulnerabilities").fetchone()["c"]

    data = [
        ["Host attivi", "Servizi aperti", "Tipi dispositivo", "Batch scansione", "Vulnerabilità note", "Host esposti (ATT&CK)"],
        [str(total_hosts), str(total_services), str(device_types), str(scans_total), str(vuln_total), str(hosts_exposed)],
    ]
    table = Table(data, colWidths=[2.8 * cm] * 6)
    table.setStyle(_table_style(stripe=False))
    return table


def _device_distribution_chart(conn, top_n=12):
    rows = conn.execute(
        "SELECT COALESCE(device_type,'unknown') device_type, COUNT(*) c "
        "FROM hosts GROUP BY device_type ORDER BY c DESC LIMIT ?", (top_n,)
    ).fetchall()
    if not rows:
        return None

    labels = [r["device_type"] for r in rows][::-1]
    values = [r["c"] for r in rows][::-1]

    drawing = Drawing(420, 24 * len(values) + 20)
    chart = HorizontalBarChart()
    chart.x = 140
    chart.y = 10
    chart.height = 24 * len(values)
    chart.width = 260
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = colors.HexColor("#4e79a7")
    chart.barLabels.nudge = 4
    chart.barLabels.fontSize = 7
    chart.barLabelFormat = "%d"
    drawing.add(chart)
    return drawing


def _top_vulnerabilities_table(conn, limit=20):
    rows = conn.execute(
        """SELECT hv.cve_id, hv.cvss, hv.port, hv.source, h.ip,
                  COALESCE(h.device_type, 'unknown') device_type
           FROM host_vulnerabilities hv
           JOIN hosts h ON h.id = hv.host_id
           ORDER BY hv.cvss DESC NULLS LAST, hv.cve_id
           LIMIT ?""", (limit,)
    ).fetchall()
    if not rows:
        return None

    data = [["CVE", "CVSS", "Host", "Tipo dispositivo", "Porta", "Fonte"]]
    for r in rows:
        data.append([
            r["cve_id"], f"{r['cvss']:.1f}" if r["cvss"] is not None else "",
            r["ip"], r["device_type"], str(r["port"] or ""), r["source"] or "",
        ])
    table = Table(data, colWidths=[3.2 * cm, 1.5 * cm, 2.8 * cm, 4 * cm, 1.8 * cm, 1.8 * cm], repeatRows=1)
    table.setStyle(_table_style())
    return table


def _attack_exposure_table(conn):
    matrix = scanner_db.attack_matrix_data(conn, only_exposed=True)
    data = [["Tattica", "Tecniche esposte", "Host esposti (max su una tecnica)"]]
    any_row = False
    for tactic in matrix["tactics"]:
        techniques = matrix["techniques_by_tactic"].get(tactic["shortname"], [])
        if not techniques:
            continue
        any_row = True
        max_hosts = max((t["host_count"] for t in techniques), default=0)
        data.append([tactic["name"], str(len(techniques)), str(max_hosts)])
    if not any_row:
        return None
    table = Table(data, colWidths=[7 * cm, 4 * cm, 6 * cm], repeatRows=1)
    table.setStyle(_table_style())
    return table


def _full_hosts_table(conn):
    rows = conn.execute(
        """SELECT h.ip, COALESCE(h.device_type,'unknown') device_type, h.os_name, h.os_accuracy,
                  (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id AND s.state='open') open_ports,
                  (SELECT COUNT(*) FROM host_vulnerabilities hv WHERE hv.host_id = h.id) vuln_count
           FROM hosts h ORDER BY h.ip"""
    ).fetchall()
    if not rows:
        return None

    def ip_key(ip):
        try:
            return tuple(int(p) for p in ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    rows = sorted(rows, key=lambda r: ip_key(r["ip"]))
    data = [["IP", "Tipo dispositivo", "OS (accuratezza)", "Porte aperte", "Vulnerabilità"]]
    for r in rows:
        os_label = f"{r['os_name']} ({r['os_accuracy']}%)" if r["os_name"] else ""
        data.append([r["ip"], r["device_type"], os_label, str(r["open_ports"]), str(r["vuln_count"])])
    table = Table(data, colWidths=[3.5 * cm, 4.5 * cm, 6 * cm, 2.5 * cm, 2.5 * cm], repeatRows=1)
    table.setStyle(_table_style())
    return table


def generate_report_pdf(conn, kinds=("summary", "hosts")):
    """Genera il report PDF e ritorna i byte del file. kinds: sottoinsieme di
    ('summary', 'hosts')."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
    )
    story = []

    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    story.append(Paragraph("Report inventario di rete - ised.net", TITLE_STYLE))
    story.append(Paragraph(f"Generato il {now} - rete 10.0.0.0/8", SUBTITLE_STYLE))
    story.append(Spacer(1, 12))

    if "summary" in kinds:
        story.append(Paragraph("Riepilogo generale", H2_STYLE))
        story.append(_stat_boxes(conn))
        story.append(Spacer(1, 10))

        chart = _device_distribution_chart(conn)
        if chart:
            story.append(Paragraph("Distribuzione per tipo dispositivo (top 12)", H2_STYLE))
            story.append(chart)

        vuln_table = _top_vulnerabilities_table(conn)
        story.append(Paragraph("Top vulnerabilità per CVSS", H2_STYLE))
        story.append(vuln_table if vuln_table else Paragraph("Nessuna vulnerabilità registrata.", BODY_STYLE))

        attack_table = _attack_exposure_table(conn)
        story.append(Paragraph("Esposizione MITRE ATT&CK per tattica", H2_STYLE))
        story.append(attack_table if attack_table else Paragraph("Nessuna mappatura ATT&CK disponibile.", BODY_STYLE))

    if "hosts" in kinds:
        if "summary" in kinds:
            story.append(PageBreak())
        story.append(Paragraph("Elenco host completo", H2_STYLE))
        hosts_table = _full_hosts_table(conn)
        story.append(hosts_table if hosts_table else Paragraph("Nessun host registrato.", BODY_STYLE))

    doc.build(story)
    return buf.getvalue()


def default_filename():
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"report_ised_{stamp}.pdf"
