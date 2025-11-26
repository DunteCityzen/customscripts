import requests
import math
import time


BASE_URL = "https://www.linkedin.com/voyager/api/graphql"

# Replace with your captured queryId + variables template
QUERY_ID = "voyagerSearchDashClusters.c0f8645a22a6347486d76d5b9d985fd7"


HEADERS = {
    'Host': 'www.linkedin.com',
    'Cookie': '<entire value of cookie header>',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Accept': 'application/vnd.linkedin.normalized+json+2.1',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'X-Li-Lang': 'en_US',
    'X-Li-Track': '{"clientVersion":"1.13.38799","mpVersion":"1.13.38799","osName":"web","timezoneOffset":3,"timezone":"Africa/Nairobi","deviceFormFactor":"DESKTOP","mpName":"voyager-web","displayDensity":1,"displayWidth":1785,"displayHeight":969}',
    'X-Li-Page-Instance': 'urn:li:page:d_flagship3_company;EH0IICu3R9SoSmB+q2F2jA==',
    'Csrf-Token': '<value of header>',
    'X-Restli-Protocol-Version': '2.0.0',
    'X-Li-Pem-Metadata': 'Voyager - Organization - Member=organization-people-card',
    'Referer': 'https://www.linkedin.com/company/<company-name>/people/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Priority': 'u=0',
    'Te': 'trailers'
}

# uncomment Proxies for debugging
#proxies = {'http':'127.0.0.1:8080', 'https':'127.0.0.1:8080'}

#50 is the maximum entries that can be provided by the API
def fetch_page(start: int, count: int = 50):
    """Fetch one page of results"""
    variables = (
        f"(start:{start},origin:FACETED_SEARCH,query:(flagshipSearchIntent:ORGANIZATIONS_PEOPLE_ALUMNI,"
        f"queryParameters:List((key:currentCompany,value:List(<organization's number/id>)),"
        f"(key:resultType,value:List(ORGANIZATION_ALUMNI))),includeFiltersInResponse:true),count:{count})"
    )
    url = f"{BASE_URL}?variables={variables}&queryId={QUERY_ID}"
    resp = requests.get(url, headers=HEADERS, proxies=proxies, verify=False)
    resp.raise_for_status()
    return resp.json()

def extract_employees(data: dict):
    """Parsing out employees from API response"""
    employees = []
    included = data.get("included", [])
    for item in included:
        if "title" in item and "primarySubtitle" in item:
            name = item.get("title", {}).get("text", "").strip()
            job = item.get("primarySubtitle", {}).get("text", "").strip()
            if name:
                employees.append({"name": name, "title": job})
    return employees


if __name__ == "__main__":
    print(r"""
       █▓▒░ company_linkedin_employees_v1.0 ░▒▓█
    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ 
   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ 
             by Mr. Robot.txt
    """)
    # Step 1: Get total result count from first request
    first = fetch_page(0, 1)
    total_count = first.get("data", {}).get("data", {}).get("searchDashClustersByAll", {}).get("metadata", {}).get("totalResultCount")
    if not total_count:
        print("[!] Could not find totalResultCount in response. Check headers and query.")
        exit(1)

    print(f"[-] Total employees: {total_count}")

    # Step 2: Loop through pages of 50
    employees = []
    pages = math.ceil(total_count / 50)
    for i in range(pages):
        start = i * 50
        print(f"[-] Fetching employees {start+1} to {min(start+50, total_count)}...")
        data = fetch_page(start, 50)
        employees.extend(extract_employees(data))
        time.sleep(2)  # polite delay

    # Step 3: Output results
    for emp in employees:
        print(f"[-] {emp['name']} — {emp['title']}")

    print(f"\n[*] Done. Extracted {len(employees)} employees.")
