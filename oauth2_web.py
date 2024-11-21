# -*- coding: utf-8 -*-

import os
import flask
import secrets
import requests
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "credentials.json"

# The OAuth 2.0 access scope allows for access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://mail.google.com/",
]
API_SERVICE_NAME = "drive"
API_VERSION = "v2"

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = secrets.token_hex()


@app.route("/")
def index():
    print(json.dumps(flask.session, indent=2))
    return print_index_table()


@app.route("/gmail")
def gmail_api_request():
    if "credentials" not in flask.session:
        return flask.redirect("authorize")

    features = flask.session["features"]

    if features["gmail"]:
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **flask.session["credentials"]
        )

        gmail = googleapiclient.discovery.build("gmail", "v1", credentials=credentials)

        messages = gmail.users().labels().list(userId="me").execute()

        # Save credentials back to session in case access token was refreshed.
        # ACTION ITEM: In a production app, you likely want to save these
        #              credentials in a persistent database instead.
        flask.session["credentials"] = credentials_to_dict(credentials)

        return flask.jsonify(**messages)
    else:
        # User didn't authorize Gmail read-only permission.
        # Update UX and application accordingly
        return "<p>Gmail feature is not enabled.</p>"


@app.route("/drive")
def drive_api_request():
    if "credentials" not in flask.session:
        return flask.redirect("authorize")

    features = flask.session["features"]

    if features["drive"]:
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **flask.session["credentials"]
        )

        drive = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials
        )

        files = drive.files().list().execute()

        # Save credentials back to session in case access token was refreshed.
        # ACTION ITEM: In a production app, you likely want to save these
        #              credentials in a persistent database instead.
        flask.session["credentials"] = credentials_to_dict(credentials)

        return flask.jsonify(**files)
    else:
        # User didn't authorize read-only Drive activity permission.
        # Update UX and application accordingly
        return "<p>Drive feature is not enabled.</p>"


@app.route("/calendar")
def calendar_api_request():
    if "credentials" not in flask.session:
        return flask.redirect("authorize")

    features = flask.session["features"]

    if features["calendar"]:
        # User authorized Calendar read permission.
        # Calling the APIs, etc.
        return (
            "<p>User granted the Google Calendar read permission. "
            + "This sample code does not include code to call Calendar</p>"
        )
    else:
        # User didn't authorize Calendar read permission.
        # Update UX and application accordingly
        return "<p>Calendar feature is not enabled.</p>"


@app.route("/authorize")
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES
    )

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for("oauth2callback", _external=True)
    print(flow.redirect_uri)
    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type="offline",
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes="true",
    )

    # Store the state so the callback can verify the auth server response.
    flask.session["state"] = state

    return flask.redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session["state"]

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )
    flow.redirect_uri = flask.url_for("oauth2callback", _external=True)
    print(flow.redirect_uri)
    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials

    credentials = credentials_to_dict(credentials)
    flask.session["credentials"] = credentials

    # Check which scopes user granted
    features = check_granted_scopes(credentials)
    flask.session["features"] = features
    print(flask.session)
    return flask.redirect("/")


@app.route("/revoke")
def revoke():
    if "credentials" not in flask.session:
        return (
            'You need to <a href="/authorize">authorize</a> before '
            + "testing the code to revoke credentials."
        )

    credentials = google.oauth2.credentials.Credentials(**flask.session["credentials"])

    revoke = requests.post(
        "https://oauth2.googleapis.com/revoke",
        params={"token": credentials.token},
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    status_code = getattr(revoke, "status_code")
    if status_code == 200:
        return "Credentials successfully revoked." + print_index_table()
    else:
        return "An error occurred." + print_index_table()


@app.route("/clear")
def clear_credentials():
    if "credentials" in flask.session:
        del flask.session["credentials"]
    return "Credentials have been cleared.<br><br>" + print_index_table()


def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "granted_scopes": credentials.granted_scopes,
    }


@app.route("/clear_state")
def clear_state():
    if "state" in flask.session:
        del flask.session["state"]
    return "State has been cleared.<br><br>" + print_index_table()


def check_granted_scopes(credentials):
    features = {}
    if (
        "https://www.googleapis.com/auth/drive.metadata.readonly"
        in credentials["granted_scopes"]
    ):
        features["drive"] = True
    else:
        features["drive"] = False

    if (
        "https://www.googleapis.com/auth/calendar.readonly"
        in credentials["granted_scopes"]
    ):
        features["calendar"] = True
    else:
        features["calendar"] = False

    if "https://mail.google.com/" in credentials["granted_scopes"]:
        features["gmail"] = True
    else:
        features["gmail"] = False

    return features


def print_index_table():
    return (
        "<table>"
        + '<tr><td><a href="/gmail">Test Gmail API request</a></td>'
        + "<td>Submit an API request to /gmail and see a formatted JSON response. "
        + "    Go through the authorization flow if there are no stored "
        + "    credentials for the user.</td></tr>"
        + '<tr><td><a href="/drive">Test Google Drive API request</a></td>'
        + "<td>Submit an API request to /drive and see a formatted JSON response. "
        + "    Go through the authorization flow if there are no stored "
        + "    credentials for the user.</td></tr>"
        + '<tr><td><a href="/calendar">Test Calendar API request</a></td>'
        + "<td>Submit an API request to /calendar and see a formatted JSON response. "
        + "    Go through the authorization flow if there are no stored "
        + "    credentials for the user.</td></tr>"
        + '<tr><td><a href="/authorize">Test the auth flow directly</a></td>'
        + "<td>Go directly to the authorization flow. If there are stored "
        + "    credentials, you still might not be prompted to reauthorize "
        + "    the application.</td></tr>"
        + '<tr><td><a href="/revoke">Revoke current credentials</a></td>'
        + "<td>Revoke the access token associated with the current user "
        + "    session. After revoking credentials, if you go to the test "
        + "    page, you should see an <code>invalid_grant</code> error."
        + "</td></tr>"
        + '<tr><td><a href="/clear">Clear Flask session credentials</a></td>'
        + "<td>Clear the access token currently stored in the user session. "
        + '    After clearing the token, if you <a href="/test">test the '
        + "    API request</a> again, you should go back to the auth flow."
        + "</td></tr>"
        + '<tr><td><a href="/clear_state">Clear Flask session state</a></td>'
        + "<td>Clear the state currently stored in the user session. "
        + "</td></tr>"
        + "</table>"
    )


if __name__ == "__main__":
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # This disables the requested scopes and granted scopes check.
    # If users only grant partial request, the warning would not be thrown.
    os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run("localhost", 8080, debug=True)
