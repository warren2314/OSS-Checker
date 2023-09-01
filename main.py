import os
import time
import requests
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Alignment

def extract_artifacts_to_file(directory_path):
    artifact_version_data = []

    for root, dirs, _ in os.walk(directory_path):
        rel_path_parts = os.path.relpath(root, directory_path).split(os.path.sep)
        if len(rel_path_parts) > 0 and rel_path_parts[-1][0].isdigit():
            artifact = ".".join(rel_path_parts[:-1])
            artifact = artifact.rsplit(".", 1)[0] + "/" + artifact.rsplit(".", 1)[1] + "@" + rel_path_parts[-1]
            artifact_version_data.append(f"{artifact}")

    with open("oss_index.txt", "w") as f:
        for line in artifact_version_data:
           f.write(line + "\n")

    print("The text file has been created.")

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

    directory_path = input("Enter the directory path: ")
    extract_artifacts_to_file(directory_path)

    ecosystem = input("Enter the package ecosystem (e.g. pypi, maven, npm etc.): ").lower()

    with open('oss_index.txt', 'r') as input_file:
        packages = [line.strip() for line in input_file]

    calls_per_minute = 120
    seconds_between_calls = 60 / calls_per_minute
    chunk_size = 128
    wb = Workbook()
    ws = wb.create_sheet()
    ws.title = "Vulnerabilities"
    row = 1

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
            row += 1

        time.sleep(seconds_between_calls)

    wo_number = input("Please enter a 6-digit WO number: ")
    while len(wo_number) != 6 or not wo_number.isdigit():
        print("Invalid input. Please ensure you enter a 6-digit number.")
        wo_number = input("Please enter a 6-digit WO number: ")
        
    filename = f"WO{wo_number}_vulnerabilities.xlsx"
    wb.save(filename)
    print(f"Vulnerabilities saved to {filename}")

if __name__ == '__main__':
    main()

