from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from io import BytesIO


def generate_report(
    email_data,
    threat_result,
    url_results,
    ip_results,
    ti_results,
    forensic_timeline
):
    """
    Generate a PDF investigation report.
    """

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    story = []

    # ==========================================
    # TITLE
    # ==========================================

    story.append(
        Paragraph(
            "AI Email Threat Investigation Report",
            title_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "AI-Powered Email Threat Detection, "
            "GeoLocation and Forensic Intelligence Platform",
            normal_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # ==========================================
    # THREAT SUMMARY
    # ==========================================

    story.append(
        Paragraph(
            "1. Threat Summary",
            heading_style
        )
    )

    summary_data = [
        ["Risk Score", f"{threat_result['risk_score']}/100"],
        ["Risk Level", threat_result["risk_level"]],
        ["Classification", threat_result["classification"]],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[180, 250]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(summary_table)

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # EMAIL INFORMATION
    # ==========================================

    story.append(
        Paragraph(
            "2. Email Information",
            heading_style
        )
    )

    email_table_data = [
        ["Field", "Value"],
        ["Sender", email_data.get("sender", "Unknown")],
        ["Receiver", email_data.get("receiver", "Unknown")],
        ["Subject", email_data.get("subject", "Unknown")],
        ["Date", email_data.get("date", "Unknown")],
        ["Reply-To", email_data.get("reply_to", "Unknown")],
        ["Message ID", email_data.get("message_id", "Unknown")],
    ]

    email_table = Table(
        email_table_data,
        colWidths=[120, 310]
    )

    email_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(email_table)

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # DETECTION REASONS
    # ==========================================

    story.append(
        Paragraph(
            "3. Detection Reasons",
            heading_style
        )
    )

    if threat_result["reasons"]:

        for reason in threat_result["reasons"]:

            story.append(
                Paragraph(
                    "• " + reason,
                    normal_style
                )
            )

            story.append(
                Spacer(1, 5)
            )

    else:

        story.append(
            Paragraph(
                "No major suspicious indicators detected.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # URL ANALYSIS
    # ==========================================

    story.append(
        Paragraph(
            "4. URL Security Analysis",
            heading_style
        )
    )

    if url_results:

        url_table_data = [
            [
                "URL",
                "Domain",
                "Risk",
                "Classification"
            ]
        ]

        for item in url_results:

            url_table_data.append([
                item["url"],
                item["domain"],
                f"{item['risk_score']}/100",
                item["classification"]
            ])

        url_table = Table(
            url_table_data,
            colWidths=[150, 120, 70, 100],
            repeatRows=1
        )

        url_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(url_table)

    else:

        story.append(
            Paragraph(
                "No URLs detected.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # IP GEOLOCATION
    # ==========================================

    story.append(
        Paragraph(
            "5. IP GeoLocation Evidence",
            heading_style
        )
    )

    if ip_results:

        ip_table_data = [
            [
                "IP Address",
                "Status",
                "Country",
                "Organization"
            ]
        ]

        for item in ip_results:

            ip_table_data.append([
                item["ip"],
                item["status"],
                item["country"],
                item["organization"]
            ])

        ip_table = Table(
            ip_table_data,
            colWidths=[100, 100, 100, 130],
            repeatRows=1
        )

        ip_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(ip_table)

    else:

        story.append(
            Paragraph(
                "No IP addresses detected.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # THREAT INTELLIGENCE
    # ==========================================

    story.append(
        Paragraph(
            "6. Threat Intelligence",
            heading_style
        )
    )

    if ti_results:

        ti_table_data = [
            [
                "Indicator",
                "Type",
                "Risk",
                "Score"
            ]
        ]

        for item in ti_results:

            ti_table_data.append([
                item["indicator"],
                item["type"],
                item["risk"],
                f"{item['score']}/100"
            ])

        ti_table = Table(
            ti_table_data,
            colWidths=[180, 100, 80, 70],
            repeatRows=1
        )

        ti_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(ti_table)

    else:

        story.append(
            Paragraph(
                "No threat intelligence indicators found.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 15)
    )

    # ==========================================
    # FORENSIC TIMELINE
    # ==========================================

    story.append(
        Paragraph(
            "7. Digital Forensic Timeline",
            heading_style
        )
    )

    timeline_data = [
        ["Event", "Timestamp", "Evidence"]
    ]

    for event in forensic_timeline:

        timeline_data.append([
            event["event"],
            str(event["timestamp"]),
            str(event["evidence"])
        ])

    timeline_table = Table(
        timeline_data,
        colWidths=[130, 120, 180],
        repeatRows=1
    )

    timeline_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(timeline_table)

    story.append(
        Spacer(1, 20)
    )

    # ==========================================
    # FOOTER
    # ==========================================

    story.append(
        Paragraph(
            "Generated by AI Email Threat Intelligence Platform",
            normal_style
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer