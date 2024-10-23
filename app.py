from flask import Flask, request, render_template, make_response
import imaplib
import email
from email.header import decode_header
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

phishing_keywords = ['account', 'bank', 'verify', 'password', 'click', 'login', 'update', 'security']


# Helper functions
def contains_suspicious_url(email_content):
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urls = re.findall(url_pattern, email_content)
    for url in urls:
        if "yourcompany.com" not in url:  # Replace with your trusted domain
            return True
    return False


def contains_phishing_content(email_content, custom_keywords):
    for keyword in phishing_keywords + custom_keywords:
        if keyword in email_content.lower():
            return keyword  # Return the keyword that was detected
    return None


def detect_phishing(subject, email_content, custom_keywords):
    reasons = []

    if contains_suspicious_url(email_content):
        reasons.append("Suspicious URL found")

    keyword_in_subject = contains_phishing_content(subject, custom_keywords)
    keyword_in_body = contains_phishing_content(email_content, custom_keywords)

    if keyword_in_subject:
        reasons.append(f"Phishing keyword found in subject: {keyword_in_subject}")
    if keyword_in_body:
        reasons.append(f"Phishing keyword found in body: {keyword_in_body}")

    if reasons:
        return "Phishing Detected", reasons
    return "No Phishing Detected", reasons


# Decode encoded email subjects
def decode_subject(encoded_subject):
    decoded_bytes, charset = decode_header(encoded_subject)[0]
    if charset is None:
        return decoded_bytes
    else:
        return decoded_bytes.decode(charset)


# Email fetching function (now with 'n' emails)
def fetch_email_content(email_address, password, n_emails):
    try:
        imap_url = 'imap.gmail.com'
        mail = imaplib.IMAP4_SSL(imap_url)
        mail.login(email_address, password)

        mail.select('Inbox')

        status, email_ids = mail.search(None, 'ALL')
        email_ids = email_ids[0].split()[-n_emails:]  # Get the latest 'n' email IDs
        emails_data = []

        for email_id in email_ids:
            status, data = mail.fetch(email_id, '(RFC822)')
            for response_part in data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    email_subject = decode_subject(msg.get('subject', ''))

                    # Extract the email body
                    email_body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))

                            if "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload is not None:
                                    email_body += payload.decode(errors='ignore')
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload is not None:
                            email_body += payload.decode(errors='ignore')

                    emails_data.append((email_subject, email_body))

        return emails_data, None

    except Exception as e:
        return None, str(e)


# Main route for the form and email check
@app.route("/", methods=['GET', 'POST'])
def index():
    email_address = ''
    password = ''
    error = None
    results = []

    # Fetch cookies or session-stored values for email and password
    if 'email' in request.cookies and 'password' in request.cookies:
        email_address = request.cookies.get('email')
        password = request.cookies.get('password')

    # Handle form submission
    if request.method == 'POST':
        email_address = request.form['email']
        password = request.form['password']
        custom_keywords = request.form['keywords'].split(',') if request.form['keywords'] else []
        remember_me = request.form.get('remember_me')
        n_emails = int(request.form['n_emails'])

        # Fetch the email content
        emails_data, error = fetch_email_content(email_address, password, n_emails)

        if error is None:
            # Check each email for phishing
            for subject, email_content in emails_data:
                result, reasons = detect_phishing(subject, email_content, custom_keywords)
                results.append({
                    'subject': subject,
                    'content': email_content,
                    'result': result,
                    'reasons': reasons
                })

            # Set cookies if 'Remember Me' is checked
            resp = make_response(render_template('result.html', emails=results))
            if remember_me:
                resp.set_cookie('email', email_address, max_age=60*60*24*30)  # 30 days
                resp.set_cookie('password', password, max_age=60*60*24*30)  # 30 days
            else:
                # Clear cookies if 'Remember Me' is unchecked
                resp.set_cookie('email', '', expires=0)
                resp.set_cookie('password', '', expires=0)

            return resp
        else:
            error = "Error fetching emails: " + error

    return render_template('index.html', email=email_address, password=password, error=error)


if __name__ == "__main__":
    app.run(debug=True)
