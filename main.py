#!/usr/bin/env python3

import time
import requests
import os
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Alignment


def get_vulnerabilities(chunk, credentials, ecosystem):
    url = "https://ossindex.sonatype.org/api/v3/component-report"

    payload = {"coordinates": [f"pkg:{ecosystem}/{package}" for package in chunk]}

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {credentials}'
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code != 200:
        print(f"Error: Received status code {response.status_code} from the API")
        response.raise_for_status()

    results = response.json()
    return results


def main():
    load_dotenv()
    credentials = os.getenv('API_KEY')

    ecosystem = input("Enter the package ecosystem (e.g. pypi, maven, npm etc.): ").lower()

    with open('python.txt', 'r') as input_file:
        packages = [line.strip() for line in input_file]

    calls_per_minute = 120
    seconds_between_calls = 60 / calls_per_minute
    chunk_size = 128

    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"
    row = 1

    #add header labels for xlsx
    ws.cell(row=row, column=1, value="Title")
    ws.cell(row=row, column=2, value="Score")
    ws.cell(row=row, column=3, value="CVE")
    ws.cell(row=row, column=4, value="Description")

    row += 1

    for i in range(0, len(packages), chunk_size):
        chunk = packages[i:i + chunk_size]
        print(f"Checking package(s): {', '.join(chunk)}")

        try:
            results = get_vulnerabilities(chunk, credentials, ecosystem)
        except requests.exceptions.RequestException as e:
            print(f"Error occurred while processing chunk: {e}")
            continue

        for result in results:
            print(f"{result['coordinates']}: {len(result['vulnerabilities'])} known vulnerabilities")
            for vulnerability in result['vulnerabilities']:
                cve = vulnerability.get('cve', 'N/A')
                title = vulnerability.get('title', 'N/A')
                cvss_score = vulnerability.get('cvssScore', 'N/A')
                description = vulnerability.get('description', 'N/A')

                ws.cell(row=row, column=1, value=f"{title}")
                ws.cell(row=row, column=2, value=f"{cvss_score}")
                ws.cell(row=row, column=3, value=f"{cve}")
                ws.cell(row=row, column=4, value=f"{description}")

                for col in range(1,5):
                    ws.cell(row=row, column=col).alignment = Alignment(wrapText=True, vertical='top', horizontal='left')

                row += 1

            row += 1 #creates an empty row between packages

        time.sleep(seconds_between_calls)

    wb.save("vulnerabilities.xlsx")


if __name__ == '__main__':
    main()
