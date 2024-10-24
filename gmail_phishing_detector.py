import os
import pickle
import base64
import re
import nltk
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticateGmail():
    creds = None

    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired() and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
            # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    service = build('gmail', 'v1', credentials=creds)
    return service

def getMessages(service):
    "Getting messages from my Gmail"
    results = service.users().messages().list(userId='me', maxResults=1).execute()
    messages = results.get('messages', [])
    return messages

def getMessageDetails(service, messageID):
    """Get the details of a message by ID."""
    message = service.users().messages().get(userId='me', id=messageID).execute()
    return message

def decodeEmail(content):
    """Decode the email content."""
    if 'parts' in content['payload']:
        if 'data' in content['payload']['parts'][0]['body']:
            data = content['payload']['parts'][0]['body']['data']
            byte_code = base64.urlsafe_b64decode(data)
            text = byte_code.decode("utf-8")
            return text
    elif 'body' in content['payload'] and 'data' in content['payload']['body']:
        # If it's a single-part message, extract the data directly
        data = content['payload']['body']['data']
        byte_code = base64.urlsafe_b64decode(data)
        text = byte_code.decode("utf-8")
        return text
    return ""

def isPhishing(emailContent):
    phishingKeywords = ['urgent', 'verify', 'account', 'update your information']

    for keyword in phishingKeywords:
        if re.search(r'\b' + keyword + r'\b', emailContent, re.IGNORECASE):
            return True
        return False


def main():
    service = authenticateGmail()
    messages = getMessages(service)

    for message in messages:
        msg_details = getMessageDetails(service, message['id'])
        emailContent = decodeEmail(msg_details)
        print(f'Email Content:\n{emailContent}\n')

    if isPhishing(emailContent):
        print("Phishing Detected")
    else:
        print("Email is Clean")


if __name__ == '__main__':
    main()