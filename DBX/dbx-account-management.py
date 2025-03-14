import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import dropbox
from dropbox.team import Feature
import csv
import json
import re
from pyexpat import features
import os

# Define Dropbox Credentials for Each College
DROPBOX_CREDENTIALS = {
    "College 1": {
        "app_key": "key",
        "app_secret": "secret",
        "team_member_id": "dbmid",
        "refresh_token": "token_goes_here"
    },
    "College 2": {
        "app_key": "key",
        "app_secret": "secret",
        "team_member_id": "dbmid",
        "refresh_token": "token_goes_here"
    },
    "College 3": {
        "app_key": "key",
        "app_secret": "secret",
        "team_member_id": "dbmid",
        "refresh_token": "token_goes_here"
    },
    # add more colleges using the format above
}

def log_change(previous_entry, updated_entry):
    """Append previous and updated details to CHANGELOG.txt with timestamp."""
    log_file = "CHANGELOG.txt"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")  # Format: YYYY-MM-DD HH:MM:SS

    log_entry = f"[{timestamp}]\n{previous_entry}\n{updated_entry}\n\n"

    # Check if file exists, if not, create it with a header
    if not os.path.exists(log_file):
        with open(log_file, "w", encoding="utf-8") as file:
            file.write("=== CUNY Dropbox Provisioning & Update Log ===\n\n")

    # Append log entry
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(log_entry)

def provision_account_in_dropbox(email, first_name, last_name, empl_id, external_id, college, role):
    """Provision a new account in Dropbox using the credentials of the selected college."""

    if college not in DROPBOX_CREDENTIALS:
        messagebox.showerror("Error", "Selected college does not have Dropbox credentials configured.")
        return

    creds = DROPBOX_CREDENTIALS[college]

    source_file_path1 = "/Acceptable Use of Data in the Cloud.pdf"
    source_file_path2 = "/Data Classification Standard.pdf"

    # Need to look up this information
    member_id_2 = "REDACTED"
    destination_file_path1 = "/Acceptable Use of Data in the Cloud.pdf"
    destination_file_path2 = "/Data Classification Standard.pdf"

    try:
        dbx_team = dropbox.DropboxTeam(
            oauth2_refresh_token=creds["refresh_token"],
            app_key=creds["app_key"],
            app_secret=creds["app_secret"]
        )

        # **🔹 Include External ID if Not Null**
        new_member_args = {
            "member_email": email,
            "member_given_name": first_name,
            "member_surname": last_name,
            "member_persistent_id": empl_id,
            "send_welcome_email": False
        }

        if external_id:  # Only add external_id if it's not empty
            new_member_args["member_external_id"] = external_id

        new_members = [dropbox.team.MemberAddV2Arg(**new_member_args)]

        force_async = False

        result = dbx_team.team_members_add_v2(new_members=new_members, force_async=force_async)
        print(result)
        result_json = json.dumps(result, default=str)
        print(result_json)
        # Process the result and handle user_on_another_team error
        if 'user_on_another_team' in result_json:
            return {"status": "error", "message": "user_on_another_team"}

        user = dropbox.team.UserSelectorArg.email(email)

        # Handle Storage Limits Based on User Role
        if role == "Student":
            try:
                dbx_team.team_member_space_limits_excluded_users_remove(users=[user])
                dbx_team.team_member_space_limits_set_custom_quota(
                    users_and_quotas=[dropbox.team.UserCustomQuotaArg(user=user, quota_gb=15)]
                )
                print(f"Set 15GB quota for student: {email}")
            except Exception as e:
                print(f"Error setting student quota: {e}")

        elif role == "Faculty / Staff":
            try:
                dbx_team.team_member_space_limits_remove_custom_quota(users=[user])
                dbx_team.team_member_space_limits_excluded_users_add(users=[user])
                print(f"Set faculty/staff storage exclusion for: {email}")
            except Exception as e:
                print(f"Error removing custom quota: {e}")

        # Getting the copy reference numbers from the account using the correct team member ID
        dbx_user1 = dbx_team.as_user(creds["team_member_id"])
        get_result1 = dbx_user1.files_copy_reference_get(path=source_file_path1)
        get_result2 = dbx_user1.files_copy_reference_get(path=source_file_path2)
        print(get_result1)
        print(get_result2)
        copy_reference1 = get_result1.copy_reference
        copy_reference2 = get_result2.copy_reference

        # New User Code to get DBMID for Copy Reference
        user = dropbox.team.UserSelectorArg.email(email)
        print(user)
        result = dbx_team.team_members_get_info_v2(members=[user])

        for info in result.members_info:
            if info.is_member_info():
                dbmid_new_user = info.get_member_info().profile.team_member_id
                print(dbmid_new_user)
            elif info.is_id_not_found():
                print("User not found.")
            else:
                print("Other scenario.")

            dbx_fileuser2 = dbx_team.as_user(dbmid_new_user)
            save_DataCloudfile = dbx_fileuser2.files_copy_reference_save(copy_reference=copy_reference1,
                                                                         path=destination_file_path1)
            print(save_DataCloudfile)

            dbx_fileuser2 = dbx_team.as_user(dbmid_new_user)
            save_DataStandardfile = dbx_fileuser2.files_copy_reference_save(copy_reference=copy_reference2,
                                                                            path=destination_file_path2)
            print(save_DataStandardfile)

            messagebox.showinfo("Success", f"Account provisioned successfully in Dropbox for '{email}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to provision account in Dropbox: {e}")

# GUI Setup
root = tk.Tk()
root.title("Dropbox Account Utility Tool")
root.minsize(600, 400)
root.resizable(True, True)

# Create Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Tab 1: Provisioning
provision_tab = ttk.Frame(notebook)
notebook.add(provision_tab, text="Provision Account")

left_frame = ttk.Frame(provision_tab, width=200)
left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

right_frame = ttk.Frame(provision_tab, width=400)
right_frame.grid(row=0, column=1, padx=70, pady=10, sticky="nsew")

# Left Frame: Check Email
ttk.Label(left_frame, text="Does Account Exist?", font=("Arial", 12, "bold")).pack(pady=10)
ttk.Label(left_frame, text="Email:").pack()
check_email_entry = ttk.Entry(left_frame)  # Left-side email field
check_email_entry.pack(pady=5)

def check_email():
    """Check if an email exists in any Dropbox team using all stored API credentials."""
    email = check_email_entry.get().strip()

    # Email validation
    if not email:
        messagebox.showerror("Error", "Please enter an email address.")
        return

    # Allowed specific domains
    allowed_domains = ["@login.cuny.edu", "@cuny.edu"]

    # Allow any subdomain like @{college_name}.cuny.edu
    if email.endswith(tuple(allowed_domains)) or email.endswith(".cuny.edu") and email.count("@") == 1:
        # Email is valid
        pass
    else:
        messagebox.showerror("Error", "Email must end with '@login.cuny.edu', '@cuny.edu', or '@{college}.cuny.edu'.")
        return


    found_in_team = None  # To store which team the email was found in

    try:
        for school, creds in DROPBOX_CREDENTIALS.items():
            try:
                # Initialize Dropbox team API with this school's credentials
                dbx_team = dropbox.DropboxTeam(
                    oauth2_refresh_token=creds["refresh_token"],
                    app_key=creds["app_key"],
                    app_secret=creds["app_secret"]
                )

                # Search for email in this specific Dropbox team
                user = dropbox.team.UserSelectorArg.email(email)
                result = dbx_team.team_members_get_info_v2([user])

                for info in result.members_info:
                    if info.is_member_info():
                        found_in_team = school  # Store the matched team
                        messagebox.showinfo(
                            "Account Found",
                            f"Email '{email}' exists in Dropbox\nTeam: {school}"
                        )
                        toggle_fields(state=tk.DISABLED)
                        return  # Stop checking once we find a match
                    elif info.is_id_not_found():
                        continue  # Continue checking next school if not found

            except dropbox.exceptions.AuthError:
                print(f"Authentication failed for {school}. Skipping...")
                continue  # If a team fails authentication, skip to next team
            except Exception as e:
                print(f"Error checking {school}: {e}")
                continue  # Log error and try the next team

        # If we finish checking all teams and no match is found
        if not found_in_team:
            messagebox.showinfo("Account Not Found", f"Email '{email}' does not exist in any Dropbox team.")
            toggle_fields(state=tk.NORMAL)  # Enable provisioning fields
            provision_email_entry.delete(0, tk.END)
            provision_email_entry.insert(0, email)  # Copy email to provisioning field

    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

check_button = ttk.Button(left_frame, text="Check Email", command=check_email)
check_button.pack(pady=10)

# Right Frame: Provision New Account
ttk.Label(right_frame, text="Provision New Account", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

ttk.Label(right_frame, text="Email:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
provision_email_entry = ttk.Entry(right_frame, state=tk.DISABLED, width=30)  # Right-side email field
provision_email_entry.grid(row=1, column=1, padx=5, pady=5)

ttk.Label(right_frame, text="First Name:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
first_name_entry = ttk.Entry(right_frame, state=tk.DISABLED, width=30)
first_name_entry.grid(row=2, column=1, padx=5, pady=5)

ttk.Label(right_frame, text="Last Name:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
last_name_entry = ttk.Entry(right_frame, state=tk.DISABLED, width=30)
last_name_entry.grid(row=3, column=1, padx=5, pady=5)

ttk.Label(right_frame, text="College Association:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
college_var = tk.StringVar()
college_dropdown = ttk.Combobox(right_frame, textvariable=college_var, state="disabled",
                                values=["College 1", "College 2", "College 3"], width=28)
college_dropdown.grid(row=5, column=1, padx=5, pady=8)
college_dropdown.set("Select College")

ttk.Label(right_frame, text="EMPL ID:").grid(row=6, column=0, sticky="w", padx=5, pady=5)
empl_id_entry = ttk.Entry(right_frame, state=tk.DISABLED, width=30)
empl_id_entry.grid(row=6, column=1, padx=5, pady=5)

ttk.Label(right_frame, text="New External ID:").grid(row=7, column=0, sticky="w", padx=5, pady=5)
new_external_id_entry = ttk.Entry(right_frame, state=tk.DISABLED, width=30)
new_external_id_entry.grid(row=7, column=1, padx=5, pady=5)

ttk.Label(right_frame, text="Role:").grid(row=8, column=0, sticky="w", padx=5, pady=5)
role_var = tk.StringVar()
role_dropdown = ttk.Combobox(right_frame, textvariable=role_var, state="disabled", values=["Faculty / Staff", "Student"], width=28)
role_dropdown.grid(row=8, column=1, padx=5, pady=8)
role_dropdown.set("Select Role")

def provision_account():
    email = provision_email_entry.get().strip()  # Right-side email field
    first_name = first_name_entry.get().strip()
    last_name = last_name_entry.get().strip()
    college = college_dropdown.get().strip()
    empl_id = empl_id_entry.get().strip()
    external_id = new_external_id_entry.get().strip()
    role = role_var.get()

    if not (email and first_name and last_name and college and role):
        messagebox.showerror("Error", "All fields must be filled out.")
        return

    if college not in DROPBOX_CREDENTIALS:
        messagebox.showerror("Error", "Selected college does not have Dropbox credentials configured.")
        return

    def provision_task():
        """Runs the provisioning process in a separate thread to keep the UI responsive."""
        try:
            root.config(cursor="watch")  # Change cursor to waiting
            root.update_idletasks()

            # Run the provisioning process and capture the result
            result = provision_account_in_dropbox(email, first_name, last_name, empl_id, external_id, college, role)

            if result.get("status") == "error":
                if result.get("message") == "user_on_another_team":
                    messagebox.showwarning(
                        "Provisioning Error",
                        f"This user has an account outside of CUNY ({email}).\n\n"
                        "Please file a ServiceNow ticket and escalate to the CUNY Dropbox Team."
                    )
                else:
                    messagebox.showerror("Provisioning Failed", f"Error: {result.get('message')}")
                return  # Stop execution to prevent logging

            # Log the new provisioned account
            previous_entry = f"[Provisioned] New Account Created"
            updated_entry = f"Email: {email} | First: {first_name} | Last: {last_name} | College: {college} | EMPL ID: {empl_id} | External ID: {external_id} | Role: {role}"
            log_change(previous_entry, updated_entry)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to provision account: {e}")

        finally:
            root.config(cursor="")  # Reset cursor to default
            root.update_idletasks()
            reset_fields()  # Reset fields after provisioning

    # Run provisioning process in a separate thread to prevent UI freezing
    threading.Thread(target=provision_task, daemon=True).start()

provision_button = ttk.Button(right_frame, text="Provision Account", state=tk.DISABLED, command=provision_account)
provision_button.grid(row=9, column=0, columnspan=2, pady=10)

def toggle_fields(state):
    """Enable or disable fields for provisioning."""
    provision_email_entry.config(state=state)
    first_name_entry.config(state=state)
    last_name_entry.config(state=state)
    college_dropdown.config(state="readonly" if state == tk.NORMAL else tk.DISABLED)
    empl_id_entry.config(state=state)
    new_external_id_entry.config(state=state)
    role_dropdown.config(state="readonly" if state == tk.NORMAL else tk.DISABLED)
    provision_button.config(state=state)

def reset_fields():
    """Reset all input fields and disable the right-side fields after provisioning."""
    check_email_entry.config(state=tk.NORMAL)  # Enable Check Email field
    check_email_entry.delete(0, tk.END)  # Clear Check Email field

    # Enable, clear, then disable fields
    provision_email_entry.config(state=tk.NORMAL)
    provision_email_entry.delete(0, tk.END)
    provision_email_entry.config(state=tk.DISABLED)

    first_name_entry.config(state=tk.NORMAL)
    first_name_entry.delete(0, tk.END)
    first_name_entry.config(state=tk.DISABLED)

    last_name_entry.config(state=tk.NORMAL)
    last_name_entry.delete(0, tk.END)
    last_name_entry.config(state=tk.DISABLED)

    college_dropdown.config(state="readonly")
    college_var.set("Select College")

    empl_id_entry.config(state=tk.NORMAL)
    empl_id_entry.delete(0, tk.END)
    empl_id_entry.config(state=tk.DISABLED)

    new_external_id_entry.config(state=tk.NORMAL)
    new_external_id_entry.delete(0, tk.END)
    new_external_id_entry.config(state=tk.DISABLED)

    role_dropdown.config(state="readonly")
    role_var.set("Select Role")

    provision_button.config(state=tk.DISABLED)  # Disable Provision Account button

    toggle_fields(state=tk.DISABLED)  # Ensure all right-side fields are disabled

# Move "Reset Fields" button to bottom center
reset_button = ttk.Button(provision_tab, text="Reset Fields", command=reset_fields)
reset_button.grid(row=10, column=0, columnspan=2, pady=10)

# Update Account Tab
update_tab = ttk.Frame(notebook)
notebook.add(update_tab, text="Update Account")

# Store previous values when looking up a user
global prev_first_name, prev_last_name, prev_email, prev_empl_id, prev_external_id, prev_college, prev_user_type

def lookup_user():
    """Fetch user details from Dropbox and populate the fields."""
    global prev_first_name, prev_last_name, prev_email, prev_empl_id, prev_external_id, prev_college, prev_user_type

    email = lookup_email_entry.get().strip()

    if not email:
        messagebox.showerror("Error", "Please enter an email address.")
        return

    # Allowed specific domains
    allowed_domains = ["login.cuny.edu", "cuny.edu"]
    email_domain = email.split("@")[-1]  # Extract domain from email

    if not any(email_domain.endswith(domain) for domain in allowed_domains):
        messagebox.showerror("Error", "Email must end with '@login.cuny.edu' or a valid '@{college}.cuny.edu'.")
        return

    found = False
    for college, creds in DROPBOX_CREDENTIALS.items():
        try:
            dbx_team = dropbox.DropboxTeam(
                oauth2_refresh_token=creds["refresh_token"],
                app_key=creds["app_key"],
                app_secret=creds["app_secret"],
            )
            user = dropbox.team.UserSelectorArg.email(email)
            result = dbx_team.team_members_get_info_v2([user])

            for info in result.members_info:
                if info.is_member_info():
                    member_info = info.get_member_info().profile
                    found = True

                    # ✅ Capture previous values BEFORE updating UI
                    prev_first_name = member_info.name.given_name
                    prev_last_name = member_info.name.surname
                    prev_email = member_info.email
                    prev_empl_id = member_info.persistent_id if member_info.persistent_id else ""
                    prev_external_id = getattr(member_info, 'external_id', "")
                    prev_college = college  # ✅ Correctly assigns the Dropbox team name
                    prev_user_type = "Faculty / Staff" if prev_external_id else "Student"

                    # Populate UI fields
                    update_first_name_entry.config(state=tk.NORMAL)
                    update_first_name_entry.delete(0, tk.END)
                    update_first_name_entry.insert(0, prev_first_name)
                    update_first_name_entry.config(state=tk.DISABLED)

                    update_last_name_entry.config(state=tk.NORMAL)
                    update_last_name_entry.delete(0, tk.END)
                    update_last_name_entry.insert(0, prev_last_name)
                    update_last_name_entry.config(state=tk.DISABLED)

                    update_email_entry.config(state=tk.NORMAL)
                    update_email_entry.delete(0, tk.END)
                    update_email_entry.insert(0, prev_email)
                    update_email_entry.config(state=tk.DISABLED)

                    update_empl_id_entry.config(state=tk.NORMAL)
                    update_empl_id_entry.delete(0, tk.END)
                    update_empl_id_entry.insert(0, prev_empl_id)
                    update_empl_id_entry.config(state=tk.DISABLED)

                    update_external_id_entry.config(state=tk.NORMAL)
                    update_external_id_entry.delete(0, tk.END)
                    update_external_id_entry.insert(0, prev_external_id if prev_external_id else "")
                    update_external_id_entry.config(state=tk.DISABLED)

                    # ✅ Update College Association (Read-only, No Checkbox)
                    update_college_entry.config(state=tk.NORMAL)
                    update_college_entry.delete(0, tk.END)
                    update_college_entry.insert(0, prev_college)
                    update_college_entry.config(state=tk.DISABLED)  # Keep it permanently disabled

                    # ✅ Set the user type
                    update_user_type_var.set(prev_user_type)

                    return

        except dropbox.exceptions.AuthError:
            continue  # Try the next team

    if not found:
        messagebox.showerror("Error", f"User '{email}' not found in Dropbox.")


# Function to enable editing when checkbox is checked
def toggle_edit(entry_widget, checkbox_var):
    """Enable or disable an entry field based on checkbox state."""
    if checkbox_var.get():
        entry_widget.config(state="normal")
        update_button.config(state="normal")  # Enable Update Account button
    else:
        entry_widget.config(state="disabled")

    # Check if any checkbox is selected, if so, enable update button
    if any([
        update_first_name_var.get(),
        update_last_name_var.get(),
        update_email_var.get(),
        update_empl_id_var.get(),
        update_external_id_var.get(),
        update_user_type_checkbox_var.get()
    ]):
        update_button.config(state="normal")  # Enable Update Account button
    else:
        update_button.config(state="disabled")  # Disable if no update is selected

# Function to update user details
def update_user():
    """Update the user's details in Dropbox."""
    global prev_first_name, prev_last_name, prev_email, prev_empl_id, prev_external_id, prev_user_type

    email = update_email_entry.get().strip()
    first_name = update_first_name_entry.get().strip()
    last_name = update_last_name_entry.get().strip()
    empl_id = update_empl_id_entry.get().strip()
    external_id = update_external_id_entry.get().strip()
    college = update_college_var.get()
    user_type = update_user_type_var.get()

    if not email:
        messagebox.showerror("Error", "No user selected for update.")
        return

    if college not in DROPBOX_CREDENTIALS:
        messagebox.showerror("Error", "Invalid college selection.")
        return

    creds = DROPBOX_CREDENTIALS[college]
    update_fields = {}
    update_log_details = []  # Track what was changed

    # ✅ Store previous account details correctly
    previous_details = f"Previous Account Details (EMPL ID: {prev_empl_id}) (College: {prev_college}) | First Name: {prev_first_name} | Last Name: {prev_last_name} | Email: {prev_email} | External ID: {prev_external_id} | User Type: {prev_user_type}"

    # ✅ Compare with previous values to log changes
    if update_first_name_var.get() and first_name != prev_first_name:
        update_fields["new_given_name"] = first_name
        update_log_details.append(f"First Name: {prev_first_name} → {first_name}")
    if update_last_name_var.get() and last_name != prev_last_name:
        update_fields["new_surname"] = last_name
        update_log_details.append(f"Last Name: {prev_last_name} → {last_name}")
    if update_email_var.get() and email != prev_email:
        update_fields["new_email"] = email
        update_log_details.append(f"Email: {prev_email} → {email}")
    if update_empl_id_var.get() and empl_id != prev_empl_id:
        update_fields["new_persistent_id"] = empl_id
        update_log_details.append(f"EMPL ID: {prev_empl_id} → {empl_id}")
    if update_external_id_var.get() and external_id != prev_external_id:
        update_fields["new_external_id"] = external_id
        update_log_details.append(f"External ID: {prev_external_id} → {external_id}")
    if update_user_type_checkbox_var.get() and user_type != prev_user_type:
        update_log_details.append(f"User Type: {prev_user_type} → {user_type}")

    # If no fields are selected, stop execution
    if not update_fields and not update_user_type_checkbox_var.get():
        messagebox.showinfo("No Changes", "No fields were selected for update.")
        return

    try:
        dbx_team = dropbox.DropboxTeam(
            oauth2_refresh_token=creds["refresh_token"],
            app_key=creds["app_key"],
            app_secret=creds["app_secret"],
        )

        user = dropbox.team.UserSelectorArg.email(email)

        # 🔹 1️⃣ Update User Profile Information if changes exist
        if update_fields:
            dbx_team.team_members_set_profile(user=user, **update_fields)
            updated_details = f"Updated Account Details (EMPL ID: {empl_id}) | Changes: {' | '.join(update_log_details)}"

        # 🔹 2️⃣ Handle Storage Limit Updates if User Type is being changed
        if update_user_type_checkbox_var.get():
            if user_type == "Student":
                try:
                    dbx_team.team_member_space_limits_excluded_users_remove(users=[user])
                    dbx_team.team_member_space_limits_set_custom_quota(
                        users_and_quotas=[dropbox.team.UserCustomQuotaArg(user=user, quota_gb=15)]
                    )
                except Exception as e:
                    print(f"Error setting custom quota: {e}")

            elif user_type == "Faculty / Staff":
                try:
                    dbx_team.team_member_space_limits_remove_custom_quota(users=[user])
                    dbx_team.team_member_space_limits_excluded_users_add(users=[user])
                except Exception as e:
                    print(f"Error removing custom quota: {e}")

        # ✅ Log previous and updated details
        log_change(previous_details, updated_details)

        messagebox.showinfo("Success", "User details updated successfully.")
        reset_update_fields()  # Reset after successful update

    except Exception as e:
        messagebox.showerror("Error", f"Failed to update user: {e}")

# Lookup User Row
ttk.Label(update_tab, text="Lookup User", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
lookup_email_entry = ttk.Entry(update_tab, width=30)
lookup_email_entry.grid(row=1, column=0, padx=5, pady=5)
lookup_button = ttk.Button(update_tab, text="Lookup", command=lookup_user)
lookup_button.grid(row=1, column=1, padx=5, pady=5)

# User Information Fields
fields = [
    ("First Name:", "update_first_name_var", "update_first_name_entry"),
    ("Last Name:", "update_last_name_var", "update_last_name_entry"),
    ("Email Address:", "update_email_var", "update_email_entry"),
    ("EMPL ID:", "update_empl_id_var", "update_empl_id_entry"),
    ("External ID:", "update_external_id_var", "update_external_id_entry"),
    ("College Association:", "update_college_var", "update_college_entry")
]

row_counter = 2
for label_text, var_name, entry_name in fields:
    ttk.Label(update_tab, text=label_text).grid(row=row_counter, column=0, sticky="w", padx=5, pady=5)

    # Create a StringVar for each field
    globals()[var_name] = tk.StringVar()

    # Create an entry field for each attribute
    globals()[entry_name] = ttk.Entry(update_tab, textvariable=globals()[var_name], width=30)
    globals()[entry_name].grid(row=row_counter, column=1, padx=5, pady=5)
    globals()[entry_name].config(state="disabled")

    if "college" not in var_name:  # Exclude College Association from having a checkbox
        globals()[f"{var_name}_check"] = tk.BooleanVar()
        checkbox = ttk.Checkbutton(
            update_tab, text="Update", variable=globals()[f"{var_name}_check"],
            command=lambda e=globals()[entry_name], v=globals()[f"{var_name}_check"]: toggle_edit(e, v)
        )
        checkbox.grid(row=row_counter, column=2, padx=5, pady=5)

    row_counter += 1

# Disable College Association field
update_college_entry.config(state="disabled")

update_user_type_var = tk.StringVar()  # Variable to store the selected user type
update_user_type_checkbox_var = tk.BooleanVar(value=False)  # Checkbox variable
ttk.Label(update_tab, text="User Type:").grid(row=8, column=0, sticky="w", padx=5, pady=5)

# Dropdown (Initially Disabled)
update_user_type_dropdown = ttk.Combobox(update_tab, textvariable=update_user_type_var,
                                         state="disabled", values=["Faculty / Staff", "Student"], width=28)
update_user_type_dropdown.grid(row=8, column=1, padx=5, pady=5)

# Checkbox to Enable/Disable Dropdown
update_user_type_checkbox = ttk.Checkbutton(update_tab, text="Update", variable=update_user_type_checkbox_var,
                                            command=lambda: toggle_edit(update_user_type_dropdown, update_user_type_checkbox_var))
update_user_type_checkbox.grid(row=8, column=2, padx=5, pady=5)  # Placed next to dropdown


def reset_update_fields():
    """Reset all input fields in the Update Account tab and ensure they are disabled."""

    # Clear Lookup Email Field
    lookup_email_entry.config(state=tk.NORMAL)
    lookup_email_entry.delete(0, tk.END)

    # Reset text fields
    update_first_name_entry.config(state=tk.NORMAL)
    update_first_name_entry.delete(0, tk.END)
    update_first_name_entry.config(state=tk.DISABLED)

    update_last_name_entry.config(state=tk.NORMAL)
    update_last_name_entry.delete(0, tk.END)
    update_last_name_entry.config(state=tk.DISABLED)

    update_email_entry.config(state=tk.NORMAL)
    update_email_entry.delete(0, tk.END)
    update_email_entry.config(state=tk.DISABLED)

    update_empl_id_entry.config(state=tk.NORMAL)
    update_empl_id_entry.delete(0, tk.END)
    update_empl_id_entry.config(state=tk.DISABLED)

    update_external_id_entry.config(state=tk.NORMAL)
    update_external_id_entry.delete(0, tk.END)
    update_external_id_entry.config(state=tk.DISABLED)

    # Reset College Association field (Read-Only)
    update_college_entry.config(state=tk.NORMAL)
    update_college_entry.delete(0, tk.END)
    update_college_entry.config(state=tk.DISABLED)

    # Reset User Type dropdown
    update_user_type_dropdown.config(state=tk.NORMAL)
    update_user_type_var.set("")  # Clear value
    update_user_type_dropdown.config(state=tk.DISABLED)

    # Uncheck all checkboxes
    update_first_name_var.set(0)
    update_last_name_var.set(0)
    update_email_var.set(0)
    update_empl_id_var.set(0)
    update_external_id_var.set(0)
    update_user_type_checkbox_var.set(0)

    # Ensure checkboxes disable the fields correctly
    toggle_edit(update_first_name_entry, update_first_name_var)
    toggle_edit(update_last_name_entry, update_last_name_var)
    toggle_edit(update_email_entry, update_email_var)
    toggle_edit(update_empl_id_entry, update_empl_id_var)
    toggle_edit(update_external_id_entry, update_external_id_var)
    toggle_edit(update_user_type_dropdown, update_user_type_checkbox_var)

    # Disable the Update Account button on reset
    update_button.config(state=tk.DISABLED)


# Update and Reset Fields Buttons
update_button = ttk.Button(update_tab, text="Update Account", command=update_user)
update_button.grid(row=9, column=0, padx=5, pady=10, sticky="e")

reset_update_button = ttk.Button(update_tab, text="Reset Fields", command=reset_update_fields)
reset_update_button.grid(row=9, column=1, padx=5, pady=10, sticky="w")



# Run Dropbox Utility Tool GUI
root.mainloop()