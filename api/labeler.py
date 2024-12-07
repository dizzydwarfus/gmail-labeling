import base64
import json
from pathlib import Path
from bs4 import BeautifulSoup


def decode_gmail_body(encoded_data: str) -> str:
    try:
        # Step 1: Decode the Base64 URL-safe string
        decoded_bytes = base64.urlsafe_b64decode(encoded_data)

        # Step 2: Decode the bytes into a string using UTF-8
        decoded_message = decoded_bytes.decode("utf-8")
        return decoded_message
    except UnicodeDecodeError as e:
        print(f"UTF-8 decoding failed: {e}")
        # If decoding fails, fall back to ignoring errors or replacing invalid bytes
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"Decoding failed: {e}")
        return None


def extract_text_from_html(
    html_content, exclude_tags=["style", "script", "head", "href", "title"]
):
    try:
        soup = BeautifulSoup(html_content, "html.parser")  # Parse the HTML
        for tag in soup(exclude_tags):
            tag.decompose()  # Remove the tag

        return soup.get_text(separator="\n").strip()  # Extract text
    except Exception as e:
        print(f"Error parsing HTML: {e}")
        return None


def read_email(file_path: str):
    with open(file_path, "r") as file:
        email = json.load(file)
    return email


if __name__ == "__main__":
    root_dir = Path(__file__).resolve().parent.parent
    data_dir = root_dir / "data"
    email_path = data_dir / "email.json"

    email = read_email(email_path)
    html_message = decode_gmail_body(email["payload"]["parts"][0]["body"]["data"])
    with open(data_dir / "email.html", "w") as file:
        file.write(html_message)
    parsed_message = extract_text_from_html(html_message)
    print(f"{parsed_message}")
