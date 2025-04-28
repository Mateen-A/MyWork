from flask import Flask, request, jsonify, render_template, session, redirect, make_response, url_for
import oauthlib.oauth1
from oauthlib.oauth1 import SignatureOnlyEndpoint
import os
from dotenv import load_dotenv
import requests
import logging
from flask_cors import CORS
from flask_session import Session
from logging.handlers import TimedRotatingFileHandler
from concurrent_log_handler import ConcurrentRotatingFileHandler

# Flask app setup
app = Flask(__name__)
CORS(app)

#### START OF LOGS ####

# Ensure the log directory exists
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Set up a concurrent rotating file handler (for multi-threaded access)
log_handler = ConcurrentRotatingFileHandler(
    filename=os.path.join(log_dir, 'demotool_app.log'),
    maxBytes=5 * 1024 * 1024,  # Rotate after 5 MB
    backupCount=5  # Keep 5 backup files
)

# Set the log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log_handler.setFormatter(formatter)

# Configure the logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)

#### END OF LOGS ####

# Load environment variables from .env file
load_dotenv()
""" 
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['SESSION_USE_SIGNER'] = True  # Sign the session ID cookie
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY')  # Ensure you have a consistent secret key

# Initialize the extension
Session(app)

app.config.update(
    SESSION_COOKIE_SAMESITE="None",  # Use "None" to allow cookies in third-party contexts
    SESSION_COOKIE_SECURE=True,      # Ensure cookies are only sent over HTTPS
) """

# Constants from .env file
CONSUMER_KEY = os.getenv('CONSUMER_KEY')
CONSUMER_SECRET = os.getenv('SHARED_SECRET')  # Changed to match typical naming
BRIGHTSPACE_API_BASE_URL = os.getenv('BRIGHTSPACE_API_BASE_URL')
DEMO_ROLE_ID = os.getenv('DEMO_ROLE_ID')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTH_URL = os.getenv('AUTH_URL')
REFRESH_TOKEN = os.getenv('REFRESH_TOKEN')

app.secret_key = APP_SECRET_KEY

#session_data = {}

# Function to validate the client
def client_key_validator(client_key):
    if client_key == CONSUMER_KEY:
        return CONSUMER_SECRET
    return None

# OAuth 1.0 endpoint setup
endpoint = SignatureOnlyEndpoint(client_key_validator)

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

def get_headers():
    access_token = get_access_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    logging.debug(f"Request headers: {headers}")
    return headers

def validate_request(request):
    logging.debug("Validating LTI request...")
    try:
        # Log all incoming request parameters
        logging.debug("Request URL: %s", request.url)
        logging.debug("Request Method: %s", request.method)
        logging.debug("Request Headers: %s", request.headers)
        logging.debug("Request Form Data: %s", request.form)

        # Ensure headers are in the correct format
        headers = {k: v for k, v in request.headers.items()}
        logging.debug("Formatted Headers for OAuth Validation: %s", headers)

        # Validate the OAuth signature
        valid, _ = endpoint.validate_request(
            request.url,
            http_method=request.method,
            body=request.form,
            headers=headers
        )
        logging.debug("LTI request valid: %s", valid)
        return valid
    except oauthlib.oauth1.OAuth1Error as e:
        logging.error("OAuth1Error: %s", e)
        return False

def update_env_file(key, value):
    """Update the .env file with the new key-value pair."""
    try:
        with open('.env', 'r') as file:
            lines = file.readlines()

        with open('.env', 'w') as file:
            for line in lines:
                if line.startswith(f'{key}='):
                    file.write(f'{key}={value}\n')
                else:
                    file.write(line)

        # If the key does not exist, add it to the end of the file
        if not any(line.startswith(f'{key}=') for line in lines):
            with open('.env', 'a') as file:
                file.write(f'{key}={value}\n')

        logging.debug(f"Updated {key} in .env file with value: {value}")
    except Exception as e:
        logging.error(f"Failed to update .env file: {e}")

@app.route('/#######')
def healthcheck():
    return render_template('#####.html')

@app.route('/########')
def demouser():
    return render_template('#####.html')

@app.route('/########', methods=['POST'])
def lti_launch():
    # Basic setup to capture necessary LTI parameters
    course_id = request.form.get('context_id')
    user_id = request.form.get('user_id')

    if not course_id or not user_id:
        return jsonify({'error': 'Course ID or User ID is missing from the LTI request'}), 400

    # Store course_id in session for later operations
    #session_data['course_id'] = course_id
    #session_data['user_id'] = user_id

    demo_student_exists = check_demo_student_exists(course_id, DEMO_ROLE_ID)

    # Redirect to a page where the user can create a demo student
    # return render_template('lti_interface.html', course_id=course_id, user_id=user_id, demo_student_exists=demo_student_exists)
    return redirect(url_for('lti_interface', course_id=course_id, user_id=user_id))

@app.route('/######')
def lti_interface():
    course_id = request.args.get('course_id')
    user_id = request.args.get('user_id')

    # Check if the demo student exists and get its user ID
    demo_user_id, demo_student_not_enrolled = check_demo_student_not_enrolled(course_id, DEMO_ROLE_ID)
    demo_student_exists = demo_user_id is not None
    demo_student_enrolled = not demo_student_not_enrolled

    return render_template('lti_interface.html', 
                           course_id=course_id, 
                           user_id=user_id, 
                           demo_user_id=demo_user_id,  # Pass demo_user_id to the template
                           demo_student_exists=demo_student_exists,
                           demo_student_enrolled=demo_student_enrolled)

def get_course_info(org_unit_id):
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/courses/{org_unit_id}'
    headers = get_headers()
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Failed to fetch course info: {response.text}")
        return None

def check_demo_student_exists(course_id, role_id):
    url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/orgUnits/{course_id}/users/"
    params = {
        'roleId': role_id
    }
    headers = get_headers()

    logging.debug(f"Request URL: {url}")
    logging.debug(f"Request Params: {params}")
    logging.debug(f"Request Headers: {headers}")

    response = requests.get(url, headers=headers, params=params)
    logging.debug(f"Response Status: {response.status_code}")
    logging.debug(f"Response Body: {response.text}")

    if response.status_code != 200 and response.text == '{"Errors":[{"Message":"Resource Not Found"}]}':
        logging.error("A demo student does not exist.")
        return None
    if response.status_code != 200 and response.text != '{"Errors":[{"Message":"Resource Not Found"}]}':
        logging.error(f"An error has occurred: {response.text}")
        return None

    try:
        enrollments = response.json().get('Items', [])
        logging.debug(f"Enrollments Count: {len(enrollments)}")
        for enrollment in enrollments:
            user_role_id = enrollment.get('Role', {}).get('Id')
            logging.debug(f"Comparing API Role ID: {user_role_id} with Expected Role ID: {role_id}")
            if int(user_role_id) == int(role_id):
                demo_user_id = enrollment['User']['Identifier']
                logging.debug(f"Matching demo student found with ID: {demo_user_id}.")
                return demo_user_id  # Return the demo_user_id directly
        logging.debug("No matching demo student found.")
        return None
    except (KeyError, ValueError) as e:
        logging.error(f"Error processing response: {e}")
        return None

def check_demo_student_not_enrolled(course_id, role_id):
    """
    Checks if a demo student exists in the Brightspace instance with the OrgDefinedId format "ZZDemo.{course_id}"
    but is not enrolled in the current course.
    """
    org_defined_id = f'ZZDemo.{course_id}'
    
    # First, check if the demo student exists in the Brightspace instance
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/users/?orgDefinedId={org_defined_id}'
    headers = get_headers()
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200 and response.text == '{"Errors":[{"Message":"Resource Not Found"}]}':
        logging.error("A demo student does not exist in the system for this course.")
        return None, False
    if response.status_code != 200 and response.text != '{"Errors":[{"Message":"Resource Not Found"}]}':
        logging.error(f"An error has occurred: {response.text}")
        return None, False
    
    users = response.json()  # response.json() is a list
    if not users:
        logging.debug("No demo student found with the specified OrgDefinedId.")
        return None, False

    demo_user_id = users[0].get('UserId')
    
    # Next, check if the found demo student is enrolled in the course
    url = f"{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/orgUnits/{course_id}/users/{demo_user_id}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 404:  # Not found means the user is not enrolled
        logging.info(f"Demo student {demo_user_id} is not enrolled in course {course_id}.")
        return demo_user_id, True
    elif response.status_code == 200:
        logging.info(f"Demo student {demo_user_id} is already enrolled in course {course_id}.")
        return demo_user_id, False
    else:
        logging.error(f"Error checking enrollment status: {response.text}")
        return None, False

@app.route('/########', methods=['POST'])
def create_demo_student():
    data = request.get_json()
    course_id = data.get('course_id')
    
    if not course_id:
        logging.error("Course ID is missing in the request")
        return jsonify({'error': 'Course ID is required'}), 400

    logging.debug(f"Attempting to create a demo student for course_id={course_id}")

    # Use check_demo_student_exists API logic to check if the student exists
    demo_user_id = check_demo_student_exists(course_id, DEMO_ROLE_ID)
    if demo_user_id:
        logging.info(f"Demo student already exists for course_id={course_id}, user_id={demo_user_id}")
        return jsonify({'message': 'Demo student already exists', 'demo_user_id': demo_user_id}), 409

    try:
        # Create a new user if no demo user exists
        demo_user_id = create_user(course_id, DEMO_ROLE_ID)
        if demo_user_id:
            enrolled = enroll_user(demo_user_id, course_id, DEMO_ROLE_ID)
            if enrolled:
                logging.info(f"Demo student created and enrolled successfully for course_id={course_id}, user_id={demo_user_id}")
                return jsonify({'message': 'Demo student created and enrolled.\n\nPlease go to Classlist to impersonate Demo Student.', 'demo_user_id': demo_user_id}), 200
            else:
                logging.error("Failed to enroll demo student")
                return jsonify({'error': 'Failed to enroll demo student'}), 500
        else:
            logging.error("Failed to create demo student")
            return jsonify({'error': 'Failed to create demo student'}), 500
    except Exception as e:
        logging.error(f"Error during user creation or enrollment: {e}")
        return jsonify({'error': 'An error occurred during user creation or enrollment', 'details': str(e)}), 500

@app.route('/########', methods=['POST'])
def re_enroll_demo_student():
    data = request.get_json()
    course_id = data.get('course_id')
    demo_user_id = data.get('demo_user_id')

    if not course_id or not demo_user_id:
        logging.error("Course ID or Demo User ID is missing in the re-enrollment request")
        return jsonify({'error': 'Course ID and Demo User ID are required'}), 400

    logging.debug(f"Attempting to re-enroll demo student {demo_user_id} in course_id={course_id}")

    enrolled = enroll_user(demo_user_id, course_id, DEMO_ROLE_ID)
    if enrolled:
        logging.info(f"Demo student {demo_user_id} successfully re-enrolled in course {course_id}")
        return jsonify({'message': 'Demo student re-enrolled successfully.\n\nPlease go to Classlist to impersonate Demo Student.'}), 200
    else:
        logging.error("Failed to re-enroll demo student")
        return jsonify({'error': 'Failed to re-enroll demo student'}), 500

@app.route('/#########', methods=['POST'])
def delete_demo_student():
    data = request.get_json()
    course_id = data.get('course_id')

    # Use check_demo_student_exists to retrieve the demo_user_id
    demo_user_id = check_demo_student_exists(course_id, DEMO_ROLE_ID)

    logging.debug(f"Received delete request for course_id={course_id}, user_id={demo_user_id}")

    if not course_id or not demo_user_id:
        logging.error("Missing course_id or demo_user_id")
        return jsonify({'error': 'Course ID or User ID is missing.'}), 400

    try:
        # Unenroll the demo student from the course
        unenrolled = unenroll_user(demo_user_id, course_id)
        if unenrolled:
            # Delete the demo user account
            deleted = delete_user(demo_user_id)
            if deleted:
                logging.info(f"Demo student {demo_user_id} deleted successfully for course_id={course_id}")
                return jsonify({'message': 'Demo student deleted successfully'}), 200
            else:
                logging.error("Failed to delete demo student")
                return jsonify({'error': 'Failed to delete demo student'}), 500
        else:
            logging.error("Failed to unenroll demo student")
            return jsonify({'error': 'Failed to unenroll demo student'}), 500
    except Exception as e:
        logging.error(f"Error during user deletion or unenrollment: {e}")
        return jsonify({'error': 'An error occurred during user deletion or unenrollment', 'details': str(e)}), 500

def create_user(course_id, role_id):
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/users/'
    data = {
        'OrgDefinedId': f'####.{course_id}',
        'FirstName': '####',
        'MiddleName': "",
        'LastName': '#####',
        'ExternalEmail': 'noemail@noemail.com',
        'UserName': f'#####',
        'RoleId': role_id,
        'IsActive': True,
        'SendCreationEmail': False
    }
    headers = get_headers()
    logging.debug(f"Creating user at URL: {url} with data: {data}")
    response = requests.post(url, headers=headers, json=data)
    logging.debug(f"Create user response status: {response.status_code}")
    logging.debug(f"Create user response body: {response.text}")

    if response.status_code == 200:
        user_id = response.json().get('UserId')
        logging.info(f"User created successfully with ID: {user_id}")
        return user_id
    else:
        logging.error(f"Error creating user: {response.text}")
        return None

def enroll_user(user_id, course_id, role_id):
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/'
    data = {
        'UserId': user_id,
        'OrgUnitId': course_id,
        'RoleId': role_id
    }
    headers = get_headers()
    logging.debug(f"Enrolling user at URL: {url} with data: {data}")
    response = requests.post(url, headers=headers, json=data)
    logging.debug(f"Enroll user response status: {response.status_code}")
    logging.debug(f"Enroll user response body: {response.text}")

    if response.status_code == 200:
        logging.info(f"User {user_id} successfully enrolled in course {course_id} with role {role_id}")
        return True
    else:
        logging.error(f"Error enrolling user: {response.text}")
        return False

def unenroll_user(user_id, course_id):
    # API call to unenroll the user from the course
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/orgUnits/{course_id}/users/{user_id}'
    logging.debug(f"Unenrolling user at URL: {url}")
    response = requests.delete(url, headers=get_headers())
    logging.debug(f"Unenroll user response status: {response.status_code}")
    if response.status_code != 200:
        logging.error(f"Error unenrolling user: {response.text}")
        return False
    return True

def find_demo_user(course_id):
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/enrollments/{course_id}/users/?roleId={DEMO_ROLE_ID}'
    logging.debug(f"Finding demo user at URL: {url}")
    response = requests.get(url, headers=get_headers())
    logging.debug(f"Find demo user response status: {response.status_code}")
    if response.status_code != 200:
        logging.error(f"Error finding demo user: {response.text}")
        return None
    enrollments = response.json().get('Items', [])
    for enrollment in enrollments:
        if enrollment['User']['RoleId'] == DEMO_ROLE_ID:
            logging.debug(f"Found demo user with ID: {enrollment['User']['Identifier']}")
            return enrollment['User']['Identifier']
    return None

def delete_user(user_id):
    # API call to delete the user account
    url = f'{BRIGHTSPACE_API_BASE_URL}/d2l/api/lp/1.9/users/{user_id}'
    logging.debug(f"Deleting user at URL: {url}")
    response = requests.delete(url, headers=get_headers())
    logging.debug(f"Delete user response status: {response.status_code}")
    if response.status_code != 200:
        logging.error(f"Error deleting user: {response.text}")
        return False
    return True

""" def store_demo_student_id(course_id, user_id):
    if 'demo_students' not in session:
        session_data['demo_students'] = {}
    session_data['demo_students'][course_id] = user_id
    session_data.modified = True  # Ensure changes are saved """

""" def get_demo_student_id(course_id):
    return session_data.get('demo_students', {}).get(course_id) """

""" def delete_demo_student_id(course_id):
    if 'demo_students' in session and course_id in session_data['demo_students']:
        del session_data['demo_students'][course_id]
        session_data.modified = True """

@app.errorhandler(500)
def handle_500_error(e):
    app.logger.error(f"Internal Server Error: {e}")
    return "An internal error occurred", 500

""" @app.route('/set_course_session', methods=['POST'])
def set_course_session():
    # Set course_id and user_id
    session_data['course_id'] = request.form.get('course_id')
    session_data['user_id'] = request.form.get('user_id')
    return jsonify({'status': 'Session set'}) """

""" @app.before_request
def set_session_cookie():
    if 'yourcookie' not in request.cookies:
        response = make_response()
        response.set_cookie('yourcookie', 'value', secure=True, httponly=True, samesite='None')
        session_data['cookie_set'] = True
        return response  # This line should not always execute """
    
if __name__ == '__main__':
    try:
        app.run(host="0.0.0.0", port=####)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
