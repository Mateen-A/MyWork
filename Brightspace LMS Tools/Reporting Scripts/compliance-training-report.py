# This Learning Management System (LMS) Brightspace API Tool is a simple program that pulls training grades 
# like Cybersecurity, Sexual Harrassment, Work Ethics, and much more, and using an outside PowerShell script,
# forwards the grades in a | delimited TXT file and pushes the file to an internal storage folder to be processed.


import os
import requests
import logging
from logging.handlers import TimedRotatingFileHandler
from concurrent_log_handler import ConcurrentRotatingFileHandler
from dotenv import load_dotenv
from datetime import datetime
from collections import defaultdict

# Define the path to the .env file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, '.env')

# Load environment variables from .env file
load_dotenv()

#### START OF LOGS ####

# Ensure the log directory exists
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Set up a concurrent rotating file handler (for multithreaded access)
log_handler = ConcurrentRotatingFileHandler(
    filename=os.path.join(log_dir, 'compliance_grades.log'),
    maxBytes=5 * 1024 * 1024,  # Rotate after 5 MB
    backupCount=5  # Keep 5 backup files
)

# Set the log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log_handler.setFormatter(formatter)

# Configure the logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)  # Only log INFO and above by default
logger.addHandler(log_handler)

#### END OF LOGS ####

# Constants from .env file
BRIGHTSPACE_API_BASE_URL = os.getenv('BRIGHTSPACE_API_BASE_URL')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REFRESH_TOKEN = os.getenv('REFRESH_TOKEN')
AUTH_URL = os.getenv('AUTH_URL')


def get_access_token():
    global REFRESH_TOKEN

    logging.debug("Attempting to get access token")
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': REFRESH_TOKEN,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(AUTH_URL, data=data)

    logging.debug(f"Access token request status: {response.status_code}")
    if response.status_code != 200:
        logging.error(f"Error response: {response.text}")
        raise Exception('Failed to refresh access token')

    tokens = response.json()
    access_token = tokens['access_token']

    new_refresh_token = tokens.get('refresh_token')
    if new_refresh_token and new_refresh_token != REFRESH_TOKEN:
        logging.debug("Updating refresh token")
        with open('.env', 'r') as file:
            lines = file.readlines()
        with open('.env', 'w') as file:
            for line in lines:
                if line.startswith('REFRESH_TOKEN'):
                    file.write(f'REFRESH_TOKEN={new_refresh_token}\n')
                else:
                    file.write(line)
        REFRESH_TOKEN = new_refresh_token

    return access_token


def get_headers():
    access_token = get_access_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    # Only log non-sensitive headers
    #logging.debug(f"Request headers: {{'Content-Type': '{headers['Content-Type']}'}}")
    return headers


def make_request(url):
    response = requests.get(url, headers=get_headers())
    if response.status_code == 401:
        logger.info("Access token expired. Refreshing token...")
        response = requests.get(url, headers=get_headers())
    if response.status_code != 200:
        logger.error(f"Failed to make request: {response.status_code}")
        logger.error(response.text)
        return None
    return response.json()

def get_grades(org_id):
    grades = []  # Store all grades
    url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/le/1.75/{org_id}/grades/final/values/"
    page_size = 200  # Request maximum of 200 items per page
    bookmark = None
    bookmark_user_id = None  # Initialize optional bookmarkUserId

    while True:
        # Construct the paginated URL
        paginated_url = f"{url}?pageSize={page_size}"
        if bookmark:
            paginated_url += f"&bookmark={bookmark}"
        if bookmark_user_id:
            paginated_url += f"&bookmarkUserId={bookmark_user_id}"

        response = requests.get(paginated_url, headers=get_headers())

        if response.status_code != 200:
            logger.error(f"Failed to fetch grades for org_id {org_id}: {response.status_code}")
            return {"Objects": grades}  # Return collected grades so far

        data = response.json()
        grades.extend(data.get("Objects", []))  # Append grades from the current page

        logger.info(f"Fetched {len(grades)} total grades so far for org_id {org_id}.")

        # Handle pagination based on the "Next" URL in the response
        next_page_url = data.get("Next")
        if not next_page_url:
            break  # No more pages, exit loop

        # Extract bookmark and bookmarkUserId from the Next URL
        next_query_params = next_page_url.split("?")[-1]
        params = dict(param.split("=") for param in next_query_params.split("&"))
        bookmark = params.get("bookmark")
        bookmark_user_id = params.get("bookmarkUserId")

    return {"Objects": grades}  # Return the complete list of grades

def get_course_details(org_id):
    url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/courses/{org_id}"
    return make_request(url)


def get_user_details(user_id):
    url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/users/{user_id}"
    return make_request(url)

def get_org_ids_by_course_code():
    logger.info("Fetching org_ids with course codes containing 'Training'")

    org_unit_ids = []
    bookmark = None

    while True:
        url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/orgstructure/?orgUnitCode=SSPARC"
        if bookmark:
            url += f"&bookmark={bookmark}"

        response = requests.get(url, headers=get_headers())
        if response.status_code != 200:
            logger.error(f"Failed to make request: {response.status_code}")
            return []

        data = response.json()
        for course in data["Items"]:
            course_code = course.get("Code", "")
            if "Training" in course_code and "_2025" in course_code:
                org_unit_ids.append(course.get("Identifier"))
                logger.info(f"Course {course_code} with Identifier {course.get('Identifier')} matches criteria.")

        bookmark = data.get("PagingInfo", {}).get("Bookmark")
        if not data.get("PagingInfo", {}).get("HasMoreItems"):
            break

    if not org_unit_ids:
        logger.warning("No courses matched the criteria 'Training' with '_2025'")

    return org_unit_ids

# Ensure the defaultdict tracks the most recent grade across all courses
student_grades = defaultdict(lambda: {"User": None, "DisplayedGrade": None, "LastModified": None, "CourseCode": None})


def process_data(org_ids):
    results = []

    for org_id in org_ids:
        logger.info(f"Processing org_id: {org_id}")

        grades_data = get_grades(org_id)
        if not grades_data or "Objects" not in grades_data:
            logger.warning(f"Invalid or empty grades data for org_id {org_id}")
            continue

        logger.info(f"Grades data for org_id {org_id}: {len(grades_data['Objects'])} records fetched.")
        course_details = get_course_details(org_id)
        if not course_details or "Code" not in course_details:
            logger.warning(f"Invalid course details for org_id {org_id}")
            continue

        course_code = course_details["Code"][:5]
        final_grades = grades_data["Objects"]

        for entry in final_grades:
            user = entry.get("User")
            if not user:
                continue  # Skip if user info is missing

            user_id = user.get("Identifier")
            grade_value = entry.get("GradeValue")
            points_numerator = grade_value.get("PointsNumerator") if grade_value else None

            if points_numerator is None or points_numerator < 80.0:
                continue  # Skip users with missing or low grades

            logger.info(f"Adding {user_id} - grade > 80 ({points_numerator})")

            last_modified = grade_value.get("LastModified")
            if last_modified:
                date_issued = datetime.strptime(last_modified, "%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                continue

            user_details = get_user_details(user_id)
            if not user_details:
                continue

            results.append({
                "OrgDefinedId": user.get("OrgDefinedId"),
                "Last Name": user_details.get("LastName"),
                "First Name": user_details.get("FirstName"),
                "Date Issued": date_issued.strftime("%d%m%Y"),
                "Completion": 100.0,
                "Course Offering Code": course_code
            })

    # Deduplicate logic: Keep only the most recent record per OrgDefinedId
    unique_results = {}
    for record in sorted(results, key=lambda x: (x['OrgDefinedId'], datetime.strptime(x['Date Issued'], "%d%m%Y")), reverse=True):
        org_defined_id = record['OrgDefinedId']
        if org_defined_id not in unique_results:
            unique_results[org_defined_id] = record  # Keep the most recent record (first in sorted list)

    return list(unique_results.values())

def json_to_txt(data, filename):
    if not data:
        logger.warning("No data to write to TXT")
        return
    try:
        keys = data[0].keys()
        with open(filename, 'w') as output_file:
            for row in data:
                output_file.write('|'.join([str(row[key]) for key in keys]) + '\n')

        logger.info(f"Data successfully written to {filename}")
    except Exception as e:
        logger.error(f"Failed to write data to TXT: {e}")


def run_training_process():
    logger.info("Starting SSPARC process")

    org_ids = get_org_ids_by_course_code()

    if not org_ids:
        logger.error("No courses with the specified criteria found")
        return "No courses with the specified criteria found"

    file_name = "ssparc.txt"

    results = process_data(org_ids)
    json_to_txt(results, file_name)

    logger.info("SSPARC process completed. File generated.")
    return "Your file has been generated. The file is saved as ssparc.txt"


if __name__ == "__main__":
    run_training_process()
