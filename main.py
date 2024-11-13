from dotenv import load_dotenv
import requests
import os

# load the API key from .env
load_dotenv()
api_key = os.getenv("NVD_API_KEY")

# define the base URL
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
headers = {"apikey": api_key}

# Define the query parameters
params = {"cpeName": "cpe:2.3:o:microsoft:windows_10:1607"}

def test_nvd_api():
    try:
        # send GET request
        response = requests.get(base_url, headers=headers, params=params)
        response.raise_for_status()  # Raises an error for HTTP errors
        data = response.json()
                
        # check for vulnerabilities key 
        if "vulnerabilities" in data:
            print("API response received successfully!")
            
            with open("nvd_vulnerabilities.txt", "w", encoding="utf-8") as file:
                # loop through each vulnerability entry and print details
                for vulnerability in data["vulnerabilities"]:
                    cve = vulnerability["cve"]
                    cve_id = cve.get("id", "N/A")
                    published_date = cve.get("published", "N/A")
                    description = cve["descriptions"][0].get("value", "No description available") if cve.get("descriptions") else "No description available"
                    
                    # print CVE details
                    file.write(f"CVE ID: {cve_id}\n")
                    file.write(f"Published Date: {published_date}\n")
                    file.write(f"Description: {description}\n")

                    # check for CVSS metrics
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV2" in metrics:
                        cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                        file.write(f"CVSS v2 Score: {cvss_v2['baseScore']}\n")
                        file.write(f"CVSS v2 Severity: {metrics['cvssMetricV2'][0]['baseSeverity']}\n")

                    if "cvssMetricV30" in metrics:
                        cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]
                        file.write(f"CVSS v3 Score: {cvss_v3['baseScore']}\n")
                        file.write(f"CVSS v3 Severity: {cvss_v3['baseSeverity']}\n")
                        
                    # Add a separator between entries
                    file.write("\n" + "-"*50 + "\n\n")
        else:
            print("API response received, but expected 'vulnerabilities' data is missing.")
            
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

# run test func
test_nvd_api()
