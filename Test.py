import smtplib
from email.mime.text import MIMEText

# Email details
sender = "nithishradhakrishnan29@gmail.com"
receiver = "nithishradhakrishnan29@gmail.com"
password = "pdke wbli xsyp fmwd"

# Message content
msg = MIMEText("Hello,\n\nThis is a test email sent using SMTP in Python.\n\nRegards,\nSender")
msg["Subject"] = "Test Email"
msg["From"] = sender
msg["To"] = receiver

# Connect to SMTP server (example: Gmail)
server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()  # Secure connection
server.login(sender, password)

# Send email
server.send_message(msg)

# Close connection
server.quit()

print("Email sent successfully!")