import os
import subprocess as sp
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.text import Text
from rich.table import Table
from typing import List

def main():
    check_if_installed()
    run_command("nmap 127.0.0.1 -T4 -sV -Pn -Ox nmap_out.xml")
    open_ports = nmap_xml_parser()
    show_port_table(open_ports)
    search_on_vulnerability_db(open_ports)
    read_vulnerability_output(open_ports)

def check_if_installed():
    nmap_loc = run_command("ls /usr/bin")
    searchsploit_loc = run_command("ls /usr/local/bin")

    loc = nmap_loc + searchsploit_loc

    console = Console()
    if "searchsploit" in loc and "nmap" in loc:
        text = Text("Both nmap and searchsploit are installed, program is starting..", style="bold green")
        console.print(text)
    else:
        text = Text("Nmap or searchsploit is missing, please install it to your system and try again.", style="bold red")
        console.print(text)

def run_command(command: str):
    command_as_list = command.split(" ")
    print(command_as_list)
    run_sp = sp.run(
        command_as_list,
        capture_output=True,
        encoding="utf-8"
    )

    return run_sp.stdout

def nmap_xml_parser():
    xml_tree = ET.parse("nmap_out.xml")
    root = xml_tree.getroot()

    open_ports = []

    for child in root.iter('port'):
        open_port = {
                "protocol": child.get("protocol"),
                "portid": child.get("portid"),
                "state": child.find('state').get("state"),
                "service_name": child.find('service').get("name"),
                "version": child[1].get("version")
        }

        open_ports.append(open_port)


    return open_ports

def show_port_table(open_ports: List[dict]):
    table = Table(title="open ports")
    table.add_column("Protocol")
    table.add_column("Port ID")
    table.add_column("State")
    table.add_column("Service Name")
    table.add_column("Version")
    for port in open_ports:
        table.add_row(
            port["protocol"],
            port["portid"],
            port["state"],
            port["service_name"],
            port["version"]
        )
    console = Console()
    console.print(table)

def search_on_vulnerability_db(open_ports: List[dict]):
    for port in open_ports:
        with open(port['service_name'], 'w') as file:
            version = port['version'] if port['version'] != None else ""
            #run_command(f"sh searchsploit {port['service_name']} {version} > ./{port['service_name']}")
            sp.run(
                ['searchsploit', port['service_name'], version],
                stdout=file
            )

def read_vulnerability_output(open_ports: List[dict]):
    console = Console()
    for port in open_ports:
        with open(port['service_name']) as temp_f:
            datafile = temp_f.readlines()
            for line in datafile:
                if port['service_name'] in line and port['version'] in line:
                    text = Text(f"Service with the name {port['service_name']} may have vulnerabilities, closing the port {port['portid']}", style="bold red")
                    console.print(text)
                    # close function here...
                    block_port(port["portid"])
                    
                else:
                    version = port['version'] if port['version'] != None else ""
                    text = Text(f"{port['service_name']} {version} has no vulnerabilities at the  moment", style="italic green")
                    console.print(text)

def block_port(portid: str):
    run_command(f"iptables -A INPUT -p tcp --dport {str} -s 127.0.0.1 -j DROP")

if __name__ == '__main__':
    main()
