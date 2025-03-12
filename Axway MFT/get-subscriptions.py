import os
import requests
import urllib3
from dotenv import load_dotenv
import tkinter as tk
from tkinter import ttk
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(InsecureRequestWarning)

# Load environment variables from .env file
load_dotenv()

# Fetch credentials from environment variables
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')

# Fetch CSRF token from environment variable
csrf_token = os.getenv('CSRF_TOKEN')

# Ensure credentials and CSRF token are found
if not username or not password:
    print("Error: Username or Password not found in .env file.")
else:
    print("Credentials successfully loaded.")

if not csrf_token:
    print("Error: CSRF token not found in .env file.")
else:
    print("CSRF token successfully loaded.")

secure_transport_base_url = "https://st-server1.cuny.edu:444"

class TWSubscriptions:
    def __init__(self, root):
        self.root = root
        self.root.title("TW Subscriptions - API Search")

        # Create the tab control
        self.tab_control = ttk.Notebook(self.root)

        # Tab 1: Search by Folder Name
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab1, text="Search by Folder Name")

        # Tab 2: Search by Account Name
        self.tab2 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab2, text="Search by Account Name")

        # Pack the tabs
        self.tab_control.pack(expand=1, fill="both")

        self.create_folder_search_tab()
        self.create_account_search_tab()

    def create_folder_search_tab(self):
        # Fields for Folder Name and Folder Path
        self.folder_name_label = tk.Label(self.tab1, text="Folder Name:")
        self.folder_name_label.grid(row=0, column=0, padx=5, pady=5)

        self.folder_name_entry = tk.Entry(self.tab1)
        self.folder_name_entry.grid(row=0, column=1, padx=5, pady=5)

        self.folder_path_label = tk.Label(self.tab1, text="Folder Path:")
        self.folder_path_label.grid(row=1, column=0, padx=5, pady=5)

        self.folder_path_entry = tk.Entry(self.tab1)
        self.folder_path_entry.grid(row=1, column=1, padx=5, pady=5)

        # Disable the other field when one is filled
        self.folder_name_entry.bind("<KeyRelease>", self.toggle_fields)
        self.folder_path_entry.bind("<KeyRelease>", self.toggle_fields)

        # Submit Button for Folder Search
        self.submit_folder_button = tk.Button(self.tab1, text="Submit", command=self.search_folder_by_name)
        self.submit_folder_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Output text box
        self.output_text = tk.Text(self.tab1, height=10, width=50)
        self.output_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def create_account_search_tab(self):
        # Field for Account Name
        self.account_name_label = tk.Label(self.tab2, text="Account Name:")
        self.account_name_label.grid(row=0, column=0, padx=5, pady=5)

        self.account_name_entry = tk.Entry(self.tab2)
        self.account_name_entry.grid(row=0, column=1, padx=5, pady=5)

        # Submit Button for Account Search
        self.submit_account_button = tk.Button(self.tab2, text="Submit", command=self.search_account_by_name)
        self.submit_account_button.grid(row=1, column=0, columnspan=2, pady=5)

        # Output text box for Account Search
        self.output_text_account = tk.Text(self.tab2, height=10, width=50)
        self.output_text_account.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def toggle_fields(self, event):
        """Enable/Disable Folder Name and Folder Path fields based on input."""
        if self.folder_name_entry.get():
            self.folder_path_entry.config(state="disabled")
        elif self.folder_path_entry.get():
            self.folder_name_entry.config(state="disabled")
        else:
            self.folder_name_entry.config(state="normal")
            self.folder_path_entry.config(state="normal")

    def search_folder_by_name(self):
        """Fetch data based on Folder Name and Folder Path."""
        folder_name = self.folder_name_entry.get()
        folder_path = self.folder_path_entry.get()

        if not folder_name and not folder_path:
            return  # Nothing to search for

        # Construct the API URL
        folder_value = folder_name if folder_name else folder_path
        url = f"{secure_transport_base_url}/api/v2.0/subscriptions?limit=300&type=SharedFolder&folder=%2F{folder_value}%2F&fields=account,folder"

        # Prepare the headers
        headers = {
            'csrfToken': csrf_token,
            'accept': 'application/json'
        }

        # Basic Authentication and disabling SSL verification
        auth = (username, password)

        print(f"Request URL: {url}")  # Debugging statement
        try:
            # Adding timeout to avoid long wait if the server doesn't respond
            response = requests.get(url, headers=headers, auth=auth, verify=False, timeout=30)  # 30 seconds timeout
            if response.status_code == 200:
                data = response.json()
                # Process the data and display results in the output box
                self.output_text.delete(1.0, tk.END)
                for item in data.get('subscriptions', []):
                    account = item['account']
                    folder = item['folder']
                    self.output_text.insert(tk.END, f"{account} - {folder}\n")
            else:
                self.handle_error(response.status_code)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}\n")

    def search_account_by_name(self):
        """Fetch data based on Account Name."""
        account_name = self.account_name_entry.get()

        if not account_name:
            return  # Nothing to search for

        # Construct the API URL
        url = f"{secure_transport_base_url}/api/v2.0/accounts/{account_name.replace(' ', '%20')}"

        # Prepare the headers
        headers = {
            'csrfToken': csrf_token,
            'accept': 'application/json'
        }

        # Basic Authentication and disabling SSL verification
        auth = (username, password)

        print(f"Request URL: {url}")  # Debugging statement
        try:
            # Adding timeout to avoid long wait if the server doesn't respond
            response = requests.get(url, headers=headers, auth=auth, verify=False, timeout=30)  # 30 seconds timeout
            if response.status_code == 200:
                data = response.json()
                # Process the data and display results in the output box
                self.output_text_account.delete(1.0, tk.END)
                account_name = data.get('account_name', 'N/A')
                folder_name = data.get('folder_name', 'N/A')
                self.output_text_account.insert(tk.END, f"{account_name} - {folder_name}\n")
            else:
                self.handle_error(response.status_code)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            self.output_text_account.delete(1.0, tk.END)
            self.output_text_account.insert(tk.END, f"Error: {str(e)}\n")

    def handle_error(self, status_code):
        """Handle errors based on the status code."""
        self.output_text_account.delete(1.0, tk.END)
        if status_code == 404:
            self.output_text_account.insert(tk.END, "Error: Not Found\n")
        elif status_code == 500:
            self.output_text_account.insert(tk.END, "Error: Server Error\n")
        else:
            self.output_text_account.insert(tk.END, f"Error: {status_code}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = TWSubscriptions(root)
    root.mainloop()
