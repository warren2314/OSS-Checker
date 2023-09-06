import os
import time
import requests
import re
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Alignment

def extract_name_and_version_v2(filename):
    base_name = filename.split('.conda')[0].split('.tar.bz2')[0]
    parts = base_name.split('-')
    name = '-'.join(parts[:-2])
    version = parts[-2]
    return f"{name}@{version}"

def process_conda_directory(directory_path):
    if not os.path.exists(directory_path):
        print(f"Directory '{directory_path}' does not exist!")
        return []

    files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f)) and (f.endswith('.conda') or f.endswith('.tar.bz2'))]
    package_details = ["Ecosystem: conda"]
    for file in files:
        result = extract_name_and_version_v2(file)
        print(result)
        package_details.append(result)
    
    return package_details

def get_package_details(filename):
    match = re.match(r'([a-zA-Z0-9_]+)-([\d.]+)', filename)
    if match:
        package_name = match.group(1)
        version = match.group(2)
        return f"{package_name}@{version}"
    else:
        return None

def process_python_directory(directory_path, output_filename):
    package_details = ["Ecosystem: pypi"]
    with open(output_filename, 'w') as output_file:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                package_detail = get_package_details(file)
                if package_detail:
                    output_file.write(package_detail + '\n')
                    print(package_detail)
                    package_details.append(package_detail)
    
    return package_details

def extract_artifacts_to_file(directory_path, structure_type):
    artifact_version_data = []

    if structure_type == "conda":
        artifact_version_data = process_conda_directory(directory_path)
    elif structure_type == "pypi":
        output_filename = os.path.join(directory_path, "python_output.txt")
        artifact_version_data = process_python_directory(directory_path, output_filename)
    else:
        print("Unsupported structure type.")
        return

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
    
    print(f"Checking URL: {url}")
    print(f"Payload: {payload}")
    

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print(f"Error: Received status code {response.status_code} from the API")
        response.raise_for_status()

    results = response.json()
    return results

def main():
    load_dotenv()
    credentials = os.getenv('API_KEY')
    print(f"Credentials: {credentials}")  # Print the credentials to verify they are being retrieved correctly

    directory_path = input("Enter the directory path: ")
    structure_types = input("Enter the structure types (maven, conda, pypi) separated by commas: ").lower().split(',')

    for structure_type in structure_types:
        structure_type = structure_type.strip()
        print(f"Processing {structure_type} structure...")
        extract_artifacts_to_file(directory_path, structure_type)

    with open('oss_index.txt', 'r') as input_file:
        ecosystem_line = input_file.readline().strip()
        ecosystem = ecosystem_line.split(": ")[1]
        print(f"Identified Ecosystem: {ecosystem}")  # Print the identified ecosystem to verify it's correct
        packages = [line.strip() for line in input_file]
        print(f"Identified Packages: {packages}")  # Print the list of packages to verify it's correct

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
            if result['vulnerabilities']:  # Check if there are any vulnerabilities
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

        time.sleep(seconds_between_calls)

    wo_number = input("Please enter a 6-digit WO number: ")
    while len(wo_number) != 6 or not wo_number.isdigit():
        print("Invalid input. Please ensure you enter a 6-digit number and exclude the WO.")
        wo_number = input("Please enter a 6-digit WO number: ")
        
    filename = f"WO{wo_number}_vulnerabilities.xlsx"
    wb.save(filename)
    print(f"Vulnerabilities saved to {filename}")

if __name__ == '__main__':
    main()

