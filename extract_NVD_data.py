import requests
import psycopg2
import json
from datetime import datetime, timedelta

# Define the NVD API URL and your API key
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
NVD_API_KEY = "57762bcb-d968-4eb3-bf3c-40a8d166fe5a"  # Replace with your valid NVD API Key

# Function to fetch CVE data for a given date range from the NVD API
def fetch_cve_data(start_date, end_date):
    url = f"{NVD_API_URL}?pubStartDate={start_date}T00:00:00.000&pubEndDate={end_date}T23:59:59.999"
    try:
        response = requests.get(url, headers={"apiKey": NVD_API_KEY})
        response.raise_for_status()  # Raise error for HTTP issues
        return response.json()  # Parse the response as JSON
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return None

# Function to insert CVE data into the PostgreSQL database
def insert_cve_data(cve_data):
    # Connect to PostgreSQL database
    conn = psycopg2.connect(
        dbname="cvedata", 
        user="postgres", 
        password="1519"
    )
    cur = conn.cursor()

    try:
        # Extract relevant fields from CVE data
        cve_id = cve_data.get('cve', {}).get('id')
        source_identifier = cve_data.get('cve', {}).get('sourceIdentifier')
        published = cve_data.get('cve', {}).get('published')
        last_modified = cve_data.get('cve', {}).get('lastModified')
        vuln_status = cve_data.get('cve', {}).get('vulnStatus')
        descriptions = json.dumps(cve_data.get('cve', {}).get('descriptions', []))
        metrics = json.dumps(cve_data.get('cve', {}).get('metrics', {}))
        weaknesses = json.dumps(cve_data.get('cve', {}).get('weaknesses', []))
        configurations = json.dumps(cve_data.get('cve', {}).get('configurations', {}))
        references = json.dumps(cve_data.get('cve', {}).get('references', []))

        # Convert published and last_modified to datetime
        published = datetime.strptime(published, '%Y-%m-%dT%H:%M:%S.%f') if published else None
        last_modified = datetime.strptime(last_modified, '%Y-%m-%dT%H:%M:%S.%f') if last_modified else None

        # Insert data into the database
        cur.execute("""
            INSERT INTO cve_entries (
                cve_id, source_identifier, published, last_modified, vuln_status, 
                descriptions, metrics, weaknesses, configurations, cve_references
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (cve_id, source_identifier, published, last_modified, vuln_status, 
              descriptions, metrics, weaknesses, configurations, references))
        conn.commit()
        print(f"CVE data for {cve_id} inserted successfully!")

    except Exception as e:
        print(f"Error inserting CVE data: {e}")
        conn.rollback()

    finally:
        cur.close()
        conn.close()

# Main function to handle fetching and storing the data
def main():
    year = 2024
    start_date = datetime(year, 1, 1)

    # Loop through each month of the year
    for month in range(1, 13):
        # Define the start and end date for the current month
        end_date = start_date + timedelta(days=31)
        end_date = end_date.replace(day=1) - timedelta(days=1)  # Get the last day of the month

        # Format dates as strings
        start_date_str = start_date.strftime('%Y-%m-%d')
        end_date_str = end_date.strftime('%Y-%m-%d')

        print(f"Fetching data for {start_date_str} to {end_date_str}...")
        cve_data = fetch_cve_data(start_date_str, end_date_str)

        # Insert data into the database
        if cve_data and 'vulnerabilities' in cve_data:
            for cve_entry in cve_data['vulnerabilities']:
                insert_cve_data(cve_entry)

        # Move to the next month
        start_date = end_date + timedelta(days=1)

if __name__ == "__main__":
    main()
