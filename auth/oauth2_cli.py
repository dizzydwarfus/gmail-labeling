#!/usr/bin/python3
#
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Performs client tasks for testing IMAP OAuth2 authentication.

To use this script, you'll need to have registered with Google as an OAuth
application and obtained an OAuth client ID and client secret.
See https://developers.google.com/identity/protocols/OAuth2 for instructions on
registering and for documentation of the APIs invoked by this code.

NOTE: The OAuth2 OOB flow isn't a thing anymore. You will need to set the
application type to "Web application" and then add https://oauth2.dance/ as an
authorised redirect URI. This is necessary for seeing the authorisation code on
a page in your browser.

This script has 3 modes of operation.

1. The first mode is used to generate and authorize an OAuth2 token, the
first step in logging in via OAuth2.

  oauth2 --user=xxx@gmail.com \
    --client_id=1038[...].apps.googleusercontent.com \
    --client_secret=VWFn8LIKAMC-MsjBMhJeOplZ \
    --generate_oauth2_token

The script will converse with Google and generate an oauth request
token, then present you with a URL you should visit in your browser to
authorize the token. Once you get the verification code from the Google
website, enter it into the script to get your OAuth access token. The output
from this command will contain the access token, a refresh token, and some
metadata about the tokens. The access token can be used until it expires, and
the refresh token lasts indefinitely, so you should record these values for
reuse.

2. The script will generate new access tokens using a refresh token.

  oauth2 --user=xxx@gmail.com \
    --client_id=1038[...].apps.googleusercontent.com \
    --client_secret=VWFn8LIKAMC-MsjBMhJeOplZ \
    --refresh_token=1/Yzm6MRy4q1xi7Dx2DuWXNgT6s37OrP_DW_IoyTum4YA

3. The script will generate an OAuth2 string that can be fed
directly to IMAP or SMTP. This is triggered with the --generate_oauth2_string
option.

  oauth2 --generate_oauth2_string --user=xxx@gmail.com \
    --access_token=ya29.AGy[...]ezLg

The output of this mode will be a base64-encoded string. To use it, connect to a
IMAPFE and pass it as the second argument to the AUTHENTICATE command.

  a AUTHENTICATE XOAUTH2 a9sha9sfs[...]9dfja929dk==
"""

import os
import json
import optparse

from utils.utils import (
    GenerateOAuth2String,
    RequireOptions,
    RefreshToken,
    TestImapAuthentication,
    TestSmtpAuthentication,
    load_client_secret_file,
    load_scope_file,
    GeneratePermissionUrl,
    AuthorizeTokens,
)


def SetupOptionParser():
    # Usage message is the module's docstring.
    parser = optparse.OptionParser(usage=__doc__)
    parser.add_option(
        "--generate-oauth2-token",
        action="store_true",
        dest="generate_oauth2_token",
        help="generates an OAuth2 token for testing",
    )
    parser.add_option(
        "--generate-oauth2-string",
        action="store_true",
        dest="generate_oauth2_string",
        help="generates an initial client response string for " "OAuth2",
    )
    parser.add_option(
        "--client-id",
        default=None,
        help="Client ID of the application that is authenticating. "
        "See OAuth2 documentation for details.",
    )
    parser.add_option(
        "--client-secret",
        default=None,
        help="Client secret of the application that is "
        "authenticating. See OAuth2 documentation for "
        "details.",
    )
    parser.add_option("--access_token", default=None, help="OAuth2 access token")
    parser.add_option("--refresh_token", default=None, help="OAuth2 refresh token")

    parser.add_option(
        "--test-imap-authentication",
        action="store_true",
        dest="test_imap_authentication",
        help="attempts to authenticate to IMAP",
    )
    parser.add_option(
        "--test-smtp-authentication",
        action="store_true",
        dest="test_smtp_authentication",
        help="attempts to authenticate to SMTP",
    )
    parser.add_option(
        "--user",
        default=None,
        help="email address of user whose account is being " "accessed",
    )
    parser.add_option(
        "--quiet",
        action="store_true",
        default=False,
        dest="quiet",
        help="Omit verbose descriptions and only print " "machine-readable outputs.",
    )
    parser.add_option(
        "--save",
        action="store_true",
        default=True,
        dest="save",
        help="Save the token to a file.",
    )

    parser.add_option(
        "--client-secret-file",
        default=os.path.join("secrets", "credentials.json"),
        help="Path to the json file containing the client secret.",
    )

    parser.add_option(
        "--scope-file",
        default=os.path.join("secrets", "scopes.json"),
        help="Path to the json file containing the scope.",
    )

    parser.add_option(
        "--service",
        default="gmail",
        help="The service for which the scope is being loaded (gmail, drive, calendar).",
    )

    parser.add_option(
        "--token-file",
        default=os.path.join("secrets", "token.json"),
        help="Path to the file containing the token.",
    )
    return parser


def main():
    options_parser = SetupOptionParser()
    (options, args) = options_parser.parse_args()

    if options.client_secret_file:
        client_secret = load_client_secret_file(options.client_secret_file)
        options.client_id = client_secret["client_id"]
        options.client_secret = client_secret["client_secret"]
        print("Loaded client secret from file.")

    if options.scope_file and options.service:
        options.scope_file = load_scope_file(options.scope_file, options.service)
        print("Loaded scope from file.")

    print(options)
    if options.refresh_token:
        RequireOptions(options, "client_id", "client_secret")
        response = RefreshToken(
            options.client_id, options.client_secret, options.refresh_token
        )

        if options.quiet:
            print(response["access_token"])

        else:
            print("Access Token: %s" % response["access_token"])
            print("Access Token Expiration Seconds: %s" % response["expires_in"])

        if options.save:
            with open("secrets/" + options.user + ".json", "w") as f:
                json.dump(obj=response, fp=f, indent=2)

    elif options.generate_oauth2_string:
        RequireOptions(options, "user", "access_token")
        oauth2_string = GenerateOAuth2String(options.user, options.access_token)

        if options.quiet:
            print(oauth2_string)
        else:
            print("OAuth2 argument:\n" + oauth2_string.decode("utf-8"))

    elif options.generate_oauth2_token:
        RequireOptions(options, "client_id", "client_secret")
        print("To authorize token, visit this url and follow the directions:")
        print(
            "%s"
            % GeneratePermissionUrl(options.client_id, " ".join(options.scope_file))
        )

        authorization_code = input("Enter verification code: ")
        response = AuthorizeTokens(
            options.client_id, options.client_secret, authorization_code
        )
        print("User: %s" % options.user)
        print("Refresh Token: %s" % response["refresh_token"])
        print("Access Token: %s" % response["access_token"])
        print("Access Token Expiration Seconds: %s" % response["expires_in"])

        if options.save:
            with open("secrets/" + options.user + ".json", "w") as f:
                json.dump(obj=response, fp=f, indent=2)

    elif options.test_imap_authentication:
        RequireOptions(options, "user", "access_token")
        TestImapAuthentication(
            GenerateOAuth2String(
                options.user, options.access_token, base64_encode=False
            )
        )

    elif options.test_smtp_authentication:
        RequireOptions(options, "user", "access_token")
        TestSmtpAuthentication(
            GenerateOAuth2String(
                options.user, options.access_token, base64_encode=False
            )
        )

    else:
        # options_parser.print_help()
        print("Nothing to do, exiting.")
        return


if __name__ == "__main__":
    main()
