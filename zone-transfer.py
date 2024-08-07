import dns.query
import dns.zone
import dns.exception
import dns.resolver
import subprocess
from prettytable import PrettyTable
import requests
import argparse

def resolve_ns_to_ip(ns_name):
    try:
        result = dns.resolver.resolve(ns_name, 'A')
        return str(result[0])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None

def zone_transfer_dnspython(domain, server):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(server, domain))
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append((name.to_text(), dns.rdatatype.to_text(rdataset.rdtype), rdata.to_text()))
        return records
    except (dns.xfr.TransferError, ConnectionResetError) as e:
        print(f"Error with dnspython: {e}")
        return None
    except (dns.exception.FormError, dns.query.BadResponse, dns.query.UnexpectedSource, dns.exception.Timeout, ValueError) as e:
        print(f"Error with dnspython: {e}")
        return None

def zone_transfer_nslookup(domain, server):
    try:
        result = subprocess.run(['nslookup', '-type=AXFR', domain, server], capture_output=True, text=True)
        if 'transfer failed' in result.stderr or result.returncode != 0:
            print("Transfer failed with nslookup.")
            return None
        records = result.stdout.splitlines()
        return records if records else None
    except Exception as e:
        print(f"Error with nslookup: {e}")
        return None

def zone_transfer_dig(domain, server):
    try:
        result = subprocess.run(['dig', '@' + server, domain, 'AXFR'], capture_output=True, text=True)
        if 'Transfer failed' in result.stderr or result.returncode != 0:
            print("Transfer failed with dig.")
            return None
        records = result.stdout.splitlines()
        return records if records else None
    except Exception as e:
        print(f"Error with dig: {e}")
        return None

def zone_transfer_nmap(domain, server):
    try:
        result = subprocess.run(['nmap', '--script', 'dns-zone-transfer', '-p 53', server], capture_output=True, text=True)
        if 'Transfer failed' in result.stderr or result.returncode != 0:
            print("Transfer failed with nmap.")
            return None
        records = result.stdout.splitlines()
        return records if records else None
    except Exception as e:
        print(f"Error with nmap: {e}")
        return None

def fetch_asn_description(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        data = response.json()
        return data.get('org', 'ASN description not available')
    except Exception as e:
        print(f"Error fetching ASN description: {e}")
        return 'ASN description not available'

def fetch_ns_records(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return [str(ns.target) for ns in ns_records]
    except Exception as e:
        print(f"Error fetching NS records: {e}")
        return []

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Perform DNS zone transfers and ASN lookup.")
    parser.add_argument('-u', '--domain', required=True, help="Domain name to perform zone transfers on.")
    args = parser.parse_args()

    domain = args.domain

    # Resolve the NS records for the domain
    ns_records = dns.resolver.resolve(domain, 'NS')
    ns_servers = [resolve_ns_to_ip(str(ns.target)) for ns in ns_records]

    all_records = []
    successful = False

    for server in ns_servers:
        if server is None:
            continue

        print(f"Checking NS server: {server}")

        # Check using dnspython
        records = zone_transfer_dnspython(domain, server)
        if records:
            successful = True
            all_records.extend(records)
            break
        elif records is None:
            # Check for specific errors
            print(f"Transfer failed or connection reset with dnspython server: {server}")
            all_records.append("No threats were found. Please try again.")
            break

        # Check using nslookup
        records = zone_transfer_nslookup(domain, server)
        if records:
            successful = True
            all_records.extend(records)
            break
        elif records is None:
            print(f"Transfer failed or connection reset with nslookup server: {server}")
            all_records.append("No threats were found. Please try again.")
            break

        # Check using dig
        records = zone_transfer_dig(domain, server)
        if records:
            successful = True
            all_records.extend(records)
            break
        elif records is None:
            print(f"Transfer failed or connection reset with dig server: {server}")
            all_records.append("No threats were found. Please try again.")
            break

        # Check using nmap
        records = zone_transfer_nmap(domain, server)
        if records:
            successful = True
            all_records.extend(records)
            break
        elif records is None:
            print(f"Transfer failed or connection reset with nmap server: {server}")
            all_records.append("No threats were found. Please try again.")
            break

    # Prepare the general information table
    general_info_table = PrettyTable()
    general_info_table.field_names = ["NS Record", "ASN Description"]

    for ns_server in ns_servers:
        if ns_server:
            asn_description = fetch_asn_description(ns_server)
            general_info_table.add_row([ns_server, asn_description])

    # Print all records
    result_table = PrettyTable()
    if successful:
        result_table.field_names = ["Threat successfully found"]
        for record in all_records:
            result_table.add_row([record])
        print(f"Zone transfer successful for domain {domain}")
    else:
        result_table.field_names = ["No threats were found. Please try again."]
        result_table.add_row(["Transfer failed."])
        print("Oh no! Unfortunately,")

    print(result_table)
    print("\nDNS INFO:")
    print(general_info_table)

if __name__ == "__main__":
    main()
