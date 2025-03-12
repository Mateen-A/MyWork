from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import os
from datetime import datetime
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from dotenv import load_dotenv
import requests
import hmac
import hashlib
import base64

# Flask app setup
app = Flask(__name__)
CORS(app)

# Load environment variables
load_dotenv()

AUTH_URL = os.getenv('AUTH_URL')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REFRESH_TOKEN = os.getenv('REFRESH_TOKEN')
BRIGHTSPACE_API_BASE_URL = os.getenv('BRIGHTSPACE_API_BASE_URL')
HMAC_SECRET_KEY = os.getenv('APP_SECRET_KEY')  # Secret key for HMAC verification

# Logging setup
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_handler = ConcurrentRotatingFileHandler(
    filename=os.path.join(log_dir, 'icwidget.log'),
    maxBytes=5 * 1024 * 1024,
    backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)

# Helper function to refresh access token
def get_access_token():
    """Refresh and retrieve an access token."""
    global REFRESH_TOKEN
    try:
        logger.debug("Refreshing access token...")
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': REFRESH_TOKEN,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        response = requests.post(AUTH_URL, data=data)
        if response.status_code != 200:
            logger.error(f"Failed to refresh access token: {response.text}")
            raise Exception("Access token refresh failed")
        tokens = response.json()
        new_access_token = tokens['access_token']
        new_refresh_token = tokens.get('refresh_token')
        if new_refresh_token and new_refresh_token != REFRESH_TOKEN:
            update_env_file('REFRESH_TOKEN', new_refresh_token)
            REFRESH_TOKEN = new_refresh_token
        return new_access_token
    except Exception as e:
        logger.error(f"Error refreshing access token: {e}")
        raise

def update_env_file(key, value):
    """Update a specific key-value pair in the .env file."""
    try:
        with open('.env', 'r') as file:
            lines = file.readlines()
        with open('.env', 'w') as file:
            for line in lines:
                if line.startswith(f'{key}='):
                    file.write(f'{key}={value}\n')
                else:
                    file.write(line)
            if not any(line.startswith(f'{key}=') for line in lines):
                file.write(f'{key}={value}\n')
    except Exception as e:
        logger.error(f"Failed to update .env file: {e}")

def generate_hmac_signature(user_id):
    """Generate HMAC signature for a given user_id"""
    computed_signature = hmac.new(
        HMAC_SECRET_KEY.encode(),
        user_id.encode(),
        hashlib.sha256
    ).digest()

    return base64.urlsafe_b64encode(computed_signature).decode().rstrip("=")

@app.route('/generate-secure-url', methods=['POST'])
def generate_secure_url():
    """Endpoint to generate a secure signed URL for the widget iframe"""
    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'Missing user_id'}), 400

    # Remove $ prefix before signing
    sanitized_user_id = user_id.lstrip('$')

    # Generate secure HMAC signature
    hmac_signature = generate_hmac_signature(sanitized_user_id)

    # Construct the signed URL
    secure_url = f"https://act-dev.cuny.edu/ic/lti-launch?user_id={sanitized_user_id}&signature={hmac_signature}"

    return jsonify({'secure_url': secure_url})

# HMAC Signature Verification
def verify_hmac_signature(user_id, received_signature):
    """Validates the HMAC signature sent from the client."""
    try:
        # Generate HMAC using the stored secret key
        computed_signature = hmac.new(
            HMAC_SECRET_KEY.encode(),  # Ensure secret key is encoded
            user_id.encode(),  # Ensure user_id is encoded
            hashlib.sha256
        ).digest()

        # Convert to Base64 URL-safe format (matching frontend encoding)
        expected_signature = base64.urlsafe_b64encode(computed_signature).decode().rstrip("=")

        logger.debug(f"User ID: {user_id}")
        logger.debug(f"Expected HMAC: {expected_signature}")
        logger.debug(f"Received HMAC: {received_signature}")

        # Compare signatures securely
        return hmac.compare_digest(expected_signature, received_signature)
    except Exception as e:
        logger.error(f"HMAC verification error: {e}")
        return False

def determine_target_code(course_code):
    """
    Determines the target semester code based on the course code and current date,
    including handling in-between semesters for both 12/6 and non-12/6 colleges.
    """
    course_prefix = course_code[:5].upper()
    now = datetime.now()
    current_month = now.month
    current_day = now.day
    current_year = now.year % 100  # Last two digits of the year (e.g., 2024 -> 24)

    # Define 12/6 schools and their session start/end dates
    session_12_6 = {
        "NCC01": {"Fall1": (9, 5), "Fall2": (1, 6), "Spring1": (3, 6), "Spring2": (6, 21)},
        "LAG01": {"Fall1": (9, 5), "Fall2": (1, 6), "Spring1": (3, 6), "Spring2": (6, 21)},
        "KCC01": {"Fall1": (9, 5), "Fall2": (1, 6), "Spring1": (3, 6), "Spring2": (6, 21)},
    }

    # Check if the course code belongs to a 12/6 school
    if course_prefix in session_12_6:
        sessions = session_12_6[course_prefix]

        # Fall Session 2 (January 6 - February 27)
        if (current_month == 1 and current_day >= sessions["Fall2"][1]) or \
           (current_month == 2 and current_day <= 27):
            logger.debug(f"Determining target code: Fall Session 2 (1249) for 12/6 college.")
            return f"1{current_year - 1}9"  # Fall Session 2 (1249)

        # Spring Semester (March 6 - June 16)
        if (current_month == 3 and current_day >= sessions["Spring1"][1]) or \
           (current_month in [4, 5]) or \
           (current_month == 6 and current_day <= 16):
            logger.debug(f"Determining target code: Spring Semester (1252).")
            return f"1{current_year}2"  # Spring Semester (1252)

        # Fall Semester (September 5 - December 14)
        if (current_month == 9 and current_day >= sessions["Fall1"][1]) or \
           (current_month in [10, 11]) or \
           (current_month == 12 and current_day <= 14):
            logger.debug(f"Determining target code: Fall Semester (1249).")
            return f"1{current_year}9"  # Fall Semester (1249)

    # Logic for non-12/6 colleges
    if not course_prefix in session_12_6:
        if current_month in [1, 2, 3, 4, 5]:
            return f"1{current_year}2"  # Spring Semester (1252)
        elif current_month in [6, 7, 8]:
            return f"1{current_year}6"  # Summer Semester (1256)
        elif current_month in [9, 10, 11]:
            return f"1{current_year}9"  # Fall Semester (1249)
        elif current_month == 12:
            if current_day < 15:
                return f"1{current_year}9"  # Fall Semester (1249)
            else:
                return f"1{current_year + 1}2"  # Spring Semester (1252)

    raise ValueError("Unable to determine target semester code")

def fetch_inactive_courses(user_id):
    """Fetch inactive courses for a user."""
    try:
        access_token = get_access_token()
        enrollments_url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/users/{user_id}/orgUnits/"
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        enrollments_response = requests.get(enrollments_url, headers=headers)
        if enrollments_response.status_code != 200:
            logger.error(f"Failed to fetch enrollments: {enrollments_response.status_code}")
            return []

        enrollments_data = enrollments_response.json()
        inactive_courses = []

        # Determine current code for both 12/6 and non-12/6 colleges
        current_code_non_126 = determine_target_code("")  # Determine current semester code for non-12/6 colleges

        logger.debug(f"Non-12/6 Current code: {current_code_non_126}")

        for enrollment in enrollments_data.get('Items', []):
            org_unit = enrollment.get('OrgUnit', {})
            if org_unit.get('Type', {}).get('Code') == "Course Offering":
                course_id = org_unit.get('Id')
                course_details_url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/courses/{course_id}"

                # Fetch course details
                course_details_response = requests.get(course_details_url, headers=headers)
                if course_details_response.status_code != 200:
                    logger.warning(f"Failed to fetch details for course_id {course_id}")
                    continue

                course_details = course_details_response.json()
                course_code = course_details.get('Code', '')

                # Extract semester code safely
                course_code_parts = course_code.split('_')
                if len(course_code_parts) < 2:  # Ensure there are enough parts
                    logger.warning(f"Course code does not have enough parts: {course_code}")
                    continue

                semester_code = course_code_parts[-2]  # Extract the second-to-last part
                logger.debug(f"Course code: {course_code}, Extracted semester code: {semester_code}")

                # Determine if the course belongs to a 12/6 college
                is_126_college = course_code[:5].upper() in ["NCC01", "LAG01", "KCC01"]

                # Handle 12/6 colleges
                if is_126_college:
                    current_code_126 = determine_target_code(course_code[:5].upper())
                    logger.debug(f"12/6 Current code: {current_code_126}")

                    if not course_details.get('IsActive', True):
                        if semester_code == current_code_126:
                            logger.debug(f"Adding 12/6 course to inactive list: {course_code}")
                            inactive_courses.append({
                                'semester': course_details.get('Semester', {}).get('Name', "Unknown Semester"),
                                'name': course_details.get('Name', "Unknown Course"),
                                'status': 'Inactive'
                            })
                        else:
                            logger.debug(f"12/6 Course {course_code} does not match current ({current_code_126}) ")

                # Handle non-12/6 colleges
                else:
                    if not course_details.get('IsActive', True):
                        if semester_code == current_code_non_126:
                            logger.debug(f"Adding non-12/6 course to inactive list: {course_code}")
                            inactive_courses.append({
                                'semester': course_details.get('Semester', {}).get('Name', "Unknown Semester"),
                                'name': course_details.get('Name', "Unknown Course"),
                                'status': 'Inactive'
                            })
                        else:
                            logger.debug(f"Non-12/6 Course {course_code} does not match current ({current_code_non_126})")

        return inactive_courses
    except Exception as e:
        logger.error(f"Error fetching inactive courses: {e}")
        return []

@app.route('/ic/lti-launch', methods=['GET', 'POST'])
def widget():
    logger.info(f"Received request with data: {request.args or request.form}")

    user_id = request.args.get('user_id') or request.form.get('user_id')
    received_signature = request.args.get('signature')

    if not user_id or not received_signature:
        logger.error("Missing user_id or signature in request")
        return jsonify({'error': 'Unauthorized'}), 401

    # Remove any '$' prefix BEFORE verification
    if user_id.startswith('$'):
        sanitized_user_id = user_id[1:]
        logger.info(f"Sanitized user_id before HMAC verification: {sanitized_user_id}")
    else:
        sanitized_user_id = user_id

    # Validate HMAC signature using sanitized user_id
    if not verify_hmac_signature(sanitized_user_id, received_signature):
        logger.error(f"Invalid HMAC signature for user_id: {sanitized_user_id}")
        return jsonify("Please refresh your browser and clear cookies/cache"), 401

    logger.info(f"Verified user_id: {sanitized_user_id}")

    # Fetch courses based on the sanitized user_id
    try:
        courses = fetch_inactive_courses(sanitized_user_id)
    except Exception as e:
        logger.error(f"Error fetching courses: {e}")
        courses = []

    return render_template('brs-widget.html', courses=courses)

@app.route('/healthcheck')
def healthcheck():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    try:
        app.run(host="0.0.0.0", port=3000, debug=True)
    except Exception as e:
        logger.error(f"Application startup error: {e}")
