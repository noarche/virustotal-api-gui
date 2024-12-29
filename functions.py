import base64
import hashlib
from PyQt5.QtWidgets import QInputDialog, QFileDialog
from requests_utils import make_request

def domain_lookup(parent, output_callback):
    domain, ok = QInputDialog.getText(parent, "Domain Lookup", "Enter domain:")
    if ok and domain:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        make_request("GET", url, output_callback)

def submit_file_hash(parent, output_callback):
    filehash, ok = QInputDialog.getText(parent, "File Hash", "Enter file hash:")
    if ok and filehash:
        url = f"https://www.virustotal.com/api/v3/files/{filehash}"
        make_request("GET", url, output_callback)

def submit_website(parent, output_callback):
    urllink, ok = QInputDialog.getText(parent, "Submit Website", "Enter URL:")
    if ok and urllink:
        encoded_url = base64.urlsafe_b64encode(urllink.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        make_request("GET", url, output_callback)

def check_website_status(parent, output_callback):
    urllink, ok = QInputDialog.getText(parent, "Check Website Status", "Enter URL:")
    if ok and urllink:
        encoded_url = base64.urlsafe_b64encode(urllink.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        make_request("GET", url, output_callback)

def upload_file(parent, output_callback):
    file_path, _ = QFileDialog.getOpenFileName(parent, "Upload File", "", "All Files (*)")
    if file_path:
        url = "https://www.virustotal.com/api/v3/files"
        try:
            with open(file_path, "rb") as file:
                files = {"file": (file_path, file, "application/octet-stream")}
                make_request("POST", url, output_callback, files=files)
        except Exception as e:
            output_callback(f"Exception occurred while uploading file: {str(e)}")

def check_ip(parent, output_callback):
    ipaddress, ok = QInputDialog.getText(parent, "Check IP Reputation", "Enter IP address:")
    if ok and ipaddress:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddress}"
        make_request("GET", url, output_callback)

def get_local_filehash_and_check(parent, output_callback):
    file_path, _ = QFileDialog.getOpenFileName(parent, "Select File", "", "All Files (*)")
    if file_path:
        try:
            sha1_hash = calculate_sha1(file_path)
            url = f"https://www.virustotal.com/api/v3/files/{sha1_hash}"
            output_callback(f"File Path: {file_path}\nSHA-1 Hash: {sha1_hash}")
            make_request("GET", url, output_callback)
        except Exception as e:
            output_callback(f"Exception occurred while calculating SHA-1 hash: {str(e)}")

def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):  # Read the file in chunks to handle large files
            sha1.update(chunk)
    return sha1.hexdigest()
