from email.message import EmailMessage


def make_message(
    *,
    sender: str = "Sender <sender@example.org>",
    recipient: str = "Recipient <recipient@example.net>",
    subject: str = "Test message",
    body: str = "Routine message body.",
    subtype: str = "plain",
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body, subtype=subtype)
    return message
