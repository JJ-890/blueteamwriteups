from email import policy
from email.parser import BytesParser
from pathlib import Path
import sys
from email.utils import parseaddr


def extract_address_info (header_value):
    """ Extract email address and domain from an email header"""
    if not header_value:
        return { "address:None, 
                "domain": None
                }
                , address = parseaddr(header_value)
    if not address or "@" not in address:
        return {
                "address": address if address else None,
                "domain": None
        }
    domain = address.split("@", 1)[1].lower()

    return {
            "address":address,
            "domain":domain
    }

def extract_sender_information(message):
    """Extract sender-related information from the email."""
    from_info = extract_address_info(message.get("From"))

    reply_to_info = extract_address_info(message.get("Reply-To"))

    return_path_info = extract_address_info(message.get("Return-Path"))

    return {
        "from": from_info,
        "reply_to": reply_to_info,
        "return_path":return_path_info
    }

def parse_email(file_path):
    """Parse an .eml file and return the email message object."""
    with open(file_path, "rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    return message


def display_headers(message):
    """Display headers relevant to an initial SOC investigation."""

    print("\n========== EMAIL HEADER ANALYSIS ==========\n")

    print(f"From:             {message.get('From', 'Not present')}")
    print(f"Reply-To:         {message.get('Reply-To', 'Not present')}")
    print(f"Return-Path:      {message.get('Return-Path', 'Not present')}")
    print(f"Subject:          {message.get('Subject', 'Not present')}")
    print(f"Date:             {message.get('Date', 'Not present')}")
    print(f"Message-ID:       {message.get('Message-ID', 'Not present')}")

    print("\nReceived:")
    received_headers = message.get_all("Received", [])

    if received_headers:
        for number, received in enumerate(received_headers, start=1):
            print(f"\n  [{number}] {received}")
    else:
        print("  Not present")

    print("\nReceived-SPF:")
    received_spf = message.get_all("Received-SPF", [])

    if received_spf:
        for result in received_spf:
            print(f"  {result}")
    else:
        print("  Not present")

    print("\nAuthentication-Results:")
    auth_results = message.get_all("Authentication-Results", [])

    if auth_results:
        for result in auth_results:
            print(f"\n  {result}")
    else:
        print("  Not present")

    print("\nDKIM-Signature:")
    dkim_signatures = message.get_all("DKIM-Signature", [])

    if dkim_signatures:
        for number, signature in enumerate(dkim_signatures, start=1):
            print(f"\n  [{number}] {signature}")
    else:
        print("  Not present")


def main():
    if len(sys.argv) != 2:
        print("Usage: python phishing_analyzer.py <email.eml>")
        sys.exit(1)

    file_path = Path(sys.argv[1])

    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    if file_path.suffix.lower() != ".eml":
        print("Error: Input file must have a .eml extension.")
        sys.exit(1)

    message = parse_email(file_path)

    sender_information = extract_sender_information(message)

    print("\n========== NORMALIZED SENDER DATA ==========\n")

    print("From:")
    print(f"  Address: {sender_information['from']['address']}")
    print(f"  Domain:  {sender_information['from']['domain']}")

    print("\nReply-To:")
    print(f"  Address: {sender_information['reply_to']['address']}")
    print(f"  Domain:  {sender_information['reply_to']['domain']}")

    print("\nReturn-Path:")
    print(f"  Address: {sender_information['return_path']['address']}")
    print(f"  Domain:  {sender_information['return_path']['domain']}")

if __name__ == "__main__":
    main()
