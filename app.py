from flask import Flask, render_template, request, send_file
from reportlab.pdfgen import canvas

import os
import xml.etree.ElementTree as ET

app = Flask(__name__)

UPLOAD_FOLDER = "scans"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def parse_nmap(xmlfile):

    tree = ET.parse(xmlfile)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        ip = host.find("address").attrib["addr"]

        ports = []

        ports_node = host.find("ports")

        if ports_node:

            for port in ports_node.findall("port"):

                state = port.find("state").attrib["state"]

                if state == "open":

                    service = port.find("service")
                    service_name = service.attrib.get("name", "Unknown")

                    risk = "Low"

                    if service_name in ["ftp", "telnet"]:
                        risk = "Critical"
                    elif service_name == "http":
                        risk = "High"
                    elif service_name in ["ssh", "mysql"]:
                        risk = "Medium"

                    ports.append({
                        "port": port.attrib["portid"],
                        "service": service_name,
                        "risk": risk
                    })

        hosts.append({
            "ip": ip,
            "ports": ports
        })

    return hosts

@app.route("/")
def home():
    return render_template("index.html", hosts=[])


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["scan"]

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)

    file.save(filepath)

    hosts = parse_nmap(filepath)

    return render_template("index.html", hosts=hosts)

@app.route("/report")
def report():

    c = canvas.Canvas("report.pdf")

    c.setFont("Helvetica-Bold", 18)
    c.drawString(180, 800, "VAPT Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, 770, "Generated Successfully")

    y = 740

    xml_files = [f for f in os.listdir("scans") if f.endswith(".xml")]

    if xml_files:
        latest = os.path.join("scans", sorted(xml_files)[-1])

        hosts = parse_nmap(latest)

        for host in hosts:
            c.drawString(50, y, f"Target : {host['ip']}")
            y -= 20

            for port in host["ports"]:
                line = f"Port {port['port']} | {port['service']} | Risk : {port['risk']}"
                c.drawString(70, y, line)
                y -= 20

                if y < 50:
                    c.showPage()
                    y = 800
    c.save()

    return send_file("report.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
