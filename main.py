import requests
import os
from dotenv import load_dotenv


def main():
    load_dotenv()
    credentials = os.getenv('API_KEY')

    with open('python.txt', 'r') as input_file:
        packages = [line.strip() for line in input_file]

    url = "https://ossindex.sonatype.org/api/v3/component-report"

    payload = {"coordinates": [f"pkg:pypi/{package}" for package in packages]}

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {credentials}'
    }

    response = requests.post(url, json=payload, headers=headers)
    results = response.json()
    print("JSON Response:", results)

    with open('vulnerabilities.txt', 'a') as output_file:
        for r in results:
            output_file.write("{}: {} known vulnerabilities\n".format(r['coordinates'], len(r['vulnerabilities'])))
            for v in r['vulnerabilities']:
                cve = v.get('cve', 'N/A')
                title = v.get('title', 'N/A')
                cvss_score = v.get('cvssScore', 'N/A')
                description = v.get('description', 'N/A')

                output_file.write('   Title:  {}\n'.format(title))
                output_file.write('   Score:  {}\n'.format(cvss_score))
                output_file.write('   CVE:    {}\n'.format(cve))
                output_file.write('   Description:  {}\n'.format(description))


if __name__ == '__main__':
    main()
