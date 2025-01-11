import re
import imaplib
import email
from email.header import decode_header
import tkinter as tk
from tkinter import simpledialog, messagebox
import os

def is_phishing(email_content):
    phishing_keywords = [
        "urgent", "immediate action", "verify your account", "click here", 
        "update your information", "security alert", "password reset", 
        "account suspended", "confirm your identity"
    ]
    
    for keyword in phishing_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_content, re.IGNORECASE):
            return True
    return False

def fetch_emails(email_user, email_pass):
    try:
        # Connect to the Gmail IMAP server
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        # Login to your account
        imap.login(email_user, email_pass)
        # Select the mailbox you want to check
        imap.select("inbox")

        # Search for all emails in the inbox
        status, messages = imap.search(None, "ALL")
        email_ids = messages[0].split()

        # Get the user's Documents directory
        documents_dir = os.path.join(os.path.expanduser("~"), "Documents")
        output_file_path = os.path.join(documents_dir, "phishing_detector_output.txt")

        with open(output_file_path, "w", encoding="utf-8") as file:
            for email_id in email_ids:
                # Fetch the email by ID
                status, msg_data = imap.fetch(email_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        # Decode the email subject
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding if encoding else "utf-8")
                        # Decode the email sender
                        from_ = msg.get("From")
                        file.write(f"Subject: {subject}\n")
                        file.write(f"From: {from_}\n")

                        # If the email message is multipart
                        if msg.is_multipart():
                            for part in msg.walk():
                                # Extract content type of email
                                content_type = part.get_content_type()
                                content_disposition = str(part.get("Content-Disposition"))

                                try:
                                    # Get the email body
                                    body = part.get_payload(decode=True).decode()
                                except:
                                    pass
                                if content_type == "text/plain" and "attachment" not in content_disposition:
                                    # Write the plain text part of the email to the file
                                    file.write(f"Body: {body}\n")
                                    # Check if the email content is phishing
                                    if is_phishing(body):
                                        file.write("This email is likely a phishing attempt.\n")
                                    else:
                                        file.write("This email seems safe.\n")
                        else:
                            # Extract content type of email
                            content_type = msg.get_content_type()
                            # Get the email body
                            body = msg.get_payload(decode=True).decode()
                            if content_type == "text/plain":
                                # Write the plain text part of the email to the file
                                file.write(f"Body: {body}\n")
                                # Check if the email content is phishing
                                if is_phishing(body):
                                    file.write("This email is likely a phishing attempt.\n")
                                else:
                                    file.write("This email seems safe.\n")
                        file.write("\n")
        # Close the connection and logout
        imap.close()
        imap.logout()
        messagebox.showinfo("Success", f"Email check completed. Results saved to {output_file_path}.")
        print(f"Results saved to {output_file_path}")
    except imaplib.IMAP4.error as e:
        messagebox.showerror("Login Failed", f"The login credentials are incorrect or IMAP access is not enabled. Error: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def start_phishing_detector():
    email_user = simpledialog.askstring("Email", "Enter your email:")
    email_pass = simpledialog.askstring("Password", "Enter your password:", show='*')
    if email_user and email_pass:
        fetch_emails(email_user, email_pass)

def stop_phishing_detector():
    root.quit()

# Create the main window
root = tk.Tk()
root.withdraw()  # Hide the main window

# Create a stop button
stop_button = tk.Button(root, text="Stop", command=stop_phishing_detector)
stop_button.pack()

# Start the phishing detector
start_phishing_detector()

# Run the Tkinter event loop
root.mainloop()