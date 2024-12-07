import os.path
import sys
import json
from optparse import OptionParser

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def RequireOptions(options, *args):
    missing = [arg for arg in args if getattr(options, arg) is None]
    if missing:
        print("Missing options: %s" % " ".join(missing))
        sys.exit(-1)


def SetupOptionParser():
    parser = OptionParser()
    parser.add_option(
        "--user",
        default=None,
        help="email address of user whose account is being accessed",
    )
    parser.add_option(
        "--client-secret-file",
        default=os.path.join("secrets", "credentials.json"),
        help="Path to the json file containing the client secret.",
    )

    parser.add_option(
        "--token-file",
        default=os.path.join("secrets", "token.json"),
        help="Path to the file containing the token.",
    )

    parser.add_option(
        "--scope-file",
        default=os.path.join("secrets", "scopes.json"),
        help="Path to the json file containing the scope.",
    )

    return parser


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    parser = SetupOptionParser()
    (options, args) = parser.parse_args()
    RequireOptions(options, "user")

    creds = None
    token_file = f"secrets/{options.user}_token.json"
    print(f"token_file: {token_file}")

    if not os.path.exists(options.client_secret_file):
        print(f"Client secret file not found at {options.client_secret_file}.")
        return
    if not os.path.exists(options.scope_file):
        print(f"Scope file not found at {options.scope_file}.")
        return

    with open(options.scope_file, "r") as file:
        SCOPES = json.load(file)["gmail"]
        print(f"SCOPES: {json.dumps(SCOPES, indent=2)}")

    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(token_file):
        try:
            print(f"Loading token from {token_file}...")
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            # print(f"creds: {creds}")
        except Exception as e:
            print(f"Error loading token: {e}")
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        try:
            print("Refreshing token...")
            creds.refresh(Request())
        except Exception as e:
            print(f"Error refreshing token: {e}")
            print("Getting new token...")
            flow = InstalledAppFlow.from_client_secrets_file(
                options.client_secret_file, SCOPES
            )
            creds = flow.run_local_server(
                port=8080,
                prompt="consent",
                access_type="offline",
            )

        # Save the credentials for the next run
        print("Saving token...")
        with open(token_file, "w") as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)
        all_labels = service.users().labels().list(userId="me").execute()
        labels = all_labels.get("labels", [])

        all_emails = service.users().messages().list(userId="me").execute()

        emails = []
        while next_page_token := all_emails.get("nextPageToken"):
            all_emails = (
                service.users()
                .messages()
                .list(userId="me", pageToken=next_page_token)
                .execute()
            )
            emails += all_emails.get("messages", [])

        if not labels:
            print("No labels found.")
            return
        print("Labels:")
        for label in labels:
            print(f"    {label["name"]}")

        if not emails:
            print("No emails found.")
            return

        print("Emails:")
        for email in emails[2:]:
            # print(email)
            message = (
                service.users().messages().get(userId="me", id=email["id"]).execute()
            )
            thread = (
                service.users()
                .threads()
                .get(userId="me", id=email["threadId"])
                .execute()
            )

            with open(
                "/Users/dizzydwarfus/Dev/gmail-labeling/data/email.json", "w"
            ) as file:
                file.write(json.dumps(message, indent=2))

            with open(
                "/Users/dizzydwarfus/Dev/gmail-labeling/data/thread.json", "w"
            ) as file:
                file.write(json.dumps(thread, indent=2))
            break

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
