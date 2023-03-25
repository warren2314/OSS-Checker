import time
import requests
import os
from dotenv import load_dotenv


def get_vulnerabilities(chunk, credentials):
    url = "https://ossindex.sonatype.org/api/v3/component-report"

    payload = {"coordinates": [f"pkg:pypi/{package}" for package in chunk]}

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {credentials}'
    }

    response = requests.post(url, json=payload, headers=headers)
    results = response.json()
    return results


def main():
    load_dotenv()
    credentials = os.getenv('API_KEY')

    with open('python.txt', 'r') as input_file:
        packages = [line.strip() for line in input_file]

    calls_per_minute = 120
    seconds_between_calls = 60 / calls_per_minute
    chunk_size = 128

    with open('vulnerabilities.txt', 'a') as output_file:
        for i in range(0, len(packages), chunk_size):
            chunk = packages[i:i + chunk_size]
            print(f"Checking package(s): {', '.join(chunk)}")
            results = get_vulnerabilities(chunk, credentials)

        for result in results:
            print(f"{result['coordinates']}: {len(result['vulnerabilities'])} known vulnerabilities")
            for vulnerability in result['vulnerabilities']:
                cve = vulnerability.get('cve', 'N/A')
                title = vulnerability.get('title', 'N/A')
                cvss_score = vulnerability.get('cvssScore', 'N/A')
                description = vulnerability.get('description', 'N/A')

                output_file.write('   Title:  {}\n'.format(title))
                output_file.write('   Score:  {}\n'.format(cvss_score))
                output_file.write('   CVE:    {}\n'.format(cve))
                output_file.write('   Description:  {}\n'.format(description))

        time.sleep(seconds_between_calls)


if __name__ == '__main__':
    main()
