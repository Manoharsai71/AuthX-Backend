import smtplib

EMAIL = "manoharsaiambati@gmail.com"
APP_PASSWORD = "pyuwvgepzkinuurw"
TO_EMAIL = "saiambati0001@gmail.com"

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL, APP_PASSWORD)
    server.sendmail(EMAIL, TO_EMAIL, "Subject: Test\n\nThis is a test email.")
    server.quit()
    print("✅ Test email sent successfully")
except smtplib.SMTPAuthenticationError as e:
    print(f"❌ Authentication failed: {e}")
