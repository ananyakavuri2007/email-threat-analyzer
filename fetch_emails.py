from threat_engine import analyze_threat
import os
import re
import time
from imapclient import IMAPClient
import pyzmail
from dotenv import load_dotenv

# -------------------------
# Load Environment Variables
# -------------------------
load_dotenv()

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

# -------------------------
# URL Extraction
# -------------------------
def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# -------------------------
# Phishing Keyword Detection
# -------------------------
def detect_phishing_keywords(text):
    keywords = ["urgent", "verify", "click here", "update", "account suspended"]
    found = []

    for word in keywords:
        if word.lower() in text.lower():
            found.append(word)

    return found

# -------------------------
# Main Email Fetcher
# -------------------------
def fetch_emails():
    try:
        with IMAPClient("imap.gmail.com", ssl=True, timeout=30) as server:
            print("Connecting to Gmail...")
            server.login(EMAIL, PASSWORD)
            print("Logged in successfully!")

            server.select_folder("INBOX")
            messages = server.search(["UNSEEN"])
            messages = messages[-5:]

            print("Unread emails found:", messages)

            BASE_DIR = os.path.dirname(os.path.abspath(__file__))
            ATTACHMENTS_DIR = os.path.join(BASE_DIR, "attachments")

            for uid in messages:
                try:
                    raw_message = server.fetch([uid], ["RFC822"])
                    message = pyzmail.PyzMessage.factory(raw_message[uid][b'RFC822'])
                except Exception as fetch_error:
                    print("Error fetching email:", fetch_error)
                    continue

                subject = message.get_subject()
                from_addr = message.get_addresses('from')
                date = message.get_decoded_header('date')

                print("\n----- EMAIL -----")
                print("From:", from_addr)
                print("Subject:", subject)
                print("Date:", date)

                email_data = {
                    "sender": from_addr,
                    "subject": subject,
                    "date": date,
                    "urls": [],
                    "phishing_keywords": [],
                    "attachments": []
                }

                # Process text
                if message.text_part:
                    try:
                        text = message.text_part.get_payload().decode(
                            message.text_part.charset or "utf-8",
                            errors="ignore"
                        )

                        print("Text Preview:", text[:100])

                        urls = extract_urls(text)
                        print("URLs found:", urls)
                        email_data["urls"] = urls

                        phishing_words = detect_phishing_keywords(text)
                        print("Phishing keywords detected:", phishing_words)
                        email_data["phishing_keywords"] = phishing_words

                    except Exception as text_error:
                        print("Error processing text:", text_error)

                # Process attachments
                for part in message.mailparts:
                    if part.filename:
                        try:
                            os.makedirs(ATTACHMENTS_DIR, exist_ok=True)

                            filepath = os.path.join(ATTACHMENTS_DIR, part.filename)
                            payload = part.get_payload()

                            with open(filepath, "wb") as f:
                                f.write(payload)

                            file_size = len(payload)
                            file_extension = part.filename.split(".")[-1]

                            print("Attachment saved:", filepath)
                            print("Attachment size:", file_size, "bytes")
                            print("Attachment extension:", file_extension)

                            email_data["attachments"].append({
                                "filename": part.filename,
                                "size": file_size,
                                "extension": file_extension
                            })

                        except Exception as attach_error:
                            print("Error saving attachment:", attach_error)

                # -------------------------------
                # Print structured data
                # -------------------------------
                print("\nStructured Email Data:")
                print(email_data)

                # -------------------------------
                # MODULE 3 — Threat Analysis
                # -------------------------------
                risk_score, threat_level, reasons = analyze_threat(
                    email_data,
                    ATTACHMENTS_DIR
                )

                print("\nThreat Score:", risk_score)
                print("Threat Level:", threat_level)

                if reasons:
                    print("Reasons:")
                    for r in reasons:
                        print("-", r)
                else:
                    print("No major threat indicators found.")

                # Small delay to avoid rate limit
                time.sleep(1)

    except Exception as e:
        print("Connection Error:", e)


if __name__ == "__main__":
    fetch_emails()

