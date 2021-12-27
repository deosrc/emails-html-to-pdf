#!/usr/bin/env python

import logging

from appconfig import load_config
from filenameutils import replace_bad_chars, replace_unpleasant_chars
from outputs import OutputToFolder, SendOutputByEmail
import pdfkit
import json
from imap_tools import MailBox, AND, MailMessageFlags
import os


def process_mail(
    output,
    mark_msg=True,
    num_emails_limit=50,
    imap_url=None,
    imap_username=None,
    imap_password=None,
    imap_folder=None,
    printfailedmessage=None,
    pdfkit_options=None,
    mail_msg_flag=None,
    filter_criteria=AND(seen=False),
    failed_messages_threshold=3,
):
    logging.info("Starting mail processing run")
    if printfailedmessage:
        logging.warning("*On failure, the Body of the email will be printed*")

    PDF_CONTENT_ERRORS = [
        "ContentNotFoundError",
        "ContentOperationNotPermittedError",
        "UnknownContentError",
        "RemoteHostClosedError",
        "ConnectionRefusedError",
        "Server refused a stream",
    ]

    failed_messages = 0

    with MailBox(imap_url).login(imap_username, imap_password, imap_folder) as mailbox:
        for i, msg in enumerate(
            mailbox.fetch(
                criteria=filter_criteria,
                limit=num_emails_limit,
                mark_seen=False,
            )
        ):
            try:
                if len(msg.attachments) != 0:
                    logging.warning(
                        f"Attachments found in {msg.subject}. Messages with attachments cannot be converted to PDF. Skipping."
                    )
                    continue

                if not msg.html.strip() == "":  # handle text only emails
                    logging.debug(f"Message '{msg.subject}' is HTML")
                    pdftext = (
                        '<meta http-equiv="Content-type" content="text/html; charset=utf-8"/>'
                        + msg.html
                    )
                else:
                    logging.debug(f"Message '{msg.subject}' is plain text")
                    pdftext = msg.text

                filename = replace_bad_chars(replace_unpleasant_chars(msg.subject))
                filename = f"{filename[:50]}.pdf"
                logging.debug(f"Using '{filename}' for PDF filename")

                logging.info(f"Exporting message '{msg.subject}' to PDF")
                options = {}
                if pdfkit_options is not None:
                    # parse WKHTMLTOPDF Options to dict
                    options = json.loads(pdfkit_options)
                try:
                    pdfkit.from_string(pdftext, filename, options=options)
                except OSError as e:
                    outputMessage = ""
                    if any([error in str(e) for error in PDF_CONTENT_ERRORS]):
                        # allow pdfs with missing images if file got created
                        if os.path.exists(filename):
                            if printfailedmessage:
                                outputMessage += f"\n{pdftext}\n"
                            outputMessage += f"\n **** HANDLED EXCEPTION ****"
                            outputMessage += f"\n\n{str(e)}\n"
                            outputMessage += f"\nOne or more remote resources failed to load, continuing without them."
                            logging.warning(outputMessage)

                        else:
                            if printfailedmessage:
                                outputMessage += f"\n{pdftext}\n"
                            outputMessage += f"\n !!!! UNHANDLED EXCEPTION with PDF Content Errors: {PDF_CONTENT_ERRORS} !!!!"
                            outputMessage += f"\n{str(e)}"
                            logging.error(outputMessage)
                            raise e
                    else:
                        if printfailedmessage:
                            outputMessage += f"\n{pdftext}\n"
                        outputMessage += f"\n !!!! UNHANDLED EXCEPTION !!!!"
                        outputMessage += f"\n{str(e)}"
                        logging.error(outputMessage)
                        raise e

                output.process(msg, [filename])

                if mark_msg and mail_msg_flag and mail_msg_flag[0] in MailMessageFlags.all:
                    mailbox.flag(msg.uid, mail_msg_flag[0], mail_msg_flag[1])
                os.remove(filename)
                logging.info(f"Finished processing of message '{msg.subject}'")
            except Exception as e:
                logging.exception(str(e))
                failed_messages += 1

                if failed_messages >= failed_messages_threshold:
                    errorMessage = f"The number of errors has reached the failed messages threshold. Processing will be halted. Please resolve issues before resuming."
                    logging.critical(errorMessage)
                    raise RuntimeError(errorMessage)

                logging.info("Continuing with next message")

    if failed_messages > 0:
        logging.warn("Completed mail processing run with one or more errors")
    else:
        logging.info("Completed mail processing run")


def _get_mail_message_flag(mail_message_flag):
    """Determine mail message flag to set on processed emails from environment variable.
    
    Only valid options are "ANSWERED", "FLAGGED", "UNFLAGGED", "DELETED" and "SEEN". Any other values will default to "SEEN".

    DRAFT flag is excluded as it can cause strange behaviour with inbound mail becoming outbound.
    RECENT flag is excluded as it is read-only

    Returns a tuple. The first part is the flag and the second is if it should be added (True) or removed (False).
    """
    mail_message_flag = config.get("input.mail_message_flag", 'SEEN').upper()
    if mail_message_flag == "ANSWERED":
        return (MailMessageFlags.ANSWERED, True)
    elif mail_message_flag == "FLAGGED":
        return (MailMessageFlags.FLAGGED, True)
    elif mail_message_flag == "UNFLAGGED":
        return (MailMessageFlags.FLAGGED, False)
    elif mail_message_flag == "DELETED":
        return (MailMessageFlags.DELETED, True)
    else:
        return (MailMessageFlags.SEEN, True)


def _determine_imap_filter(mail_message_flag):
    """Determine mail message filter to apply when searching for mail.

    A suitable value is determined from the mail message flag.
    If no suitable value can be determined, an error is raised.
    """
    # No value specified so generate a default from the message flag
    if mail_message_flag[0] == MailMessageFlags.SEEN:
        return AND(seen=(not mail_message_flag[1]))
    elif mail_message_flag[0] == MailMessageFlags.ANSWERED:
        return AND(answered=(not mail_message_flag[1]))
    elif mail_message_flag[0] == MailMessageFlags.FLAGGED:
        return AND(flagged=(not mail_message_flag[1]))
    elif mail_message_flag[0] == MailMessageFlags.DELETED and mail_message_flag[1]:
        # Search for undeleted while possible doesn't make sense
        # so just search for all
        return AND(all=True)
    else:
        # Can't determine an appropriate value so make the user supply one
        raise ValueError("Could not determine IMAP filter from mail message flag. You must specify the filter manually.")


if __name__ == "__main__":

    config = load_config()

    log_level = config.get('logging', {}).get('level', 'INFO')
    if log_level == "DEBUG":
        log_level = logging.DEBUG
    elif log_level == "INFO":
        log_level = logging.INFO
    elif log_level == "WARNING":
        log_level = logging.WARNING
    elif log_level == "ERROR":
        log_level = logging.ERROR
    else:
        logging.warning(
            f"Unrecognised logging level '{log_level}'. Defaulting to INFO level."
        )
        log_level = logging.INFO
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=log_level
    )

    printfailedmessage = config.get("logging", {}).get('output_msg_on_error', False)

    mail_msg_flag = _get_mail_message_flag(config.input.get('post_action', {}).get('flag', 'SEEN'))
    filter = config.input.imap.get('filter') if config.input.imap.get('filter') else _determine_imap_filter(mail_msg_flag)

    output = None
    if 'smtp' in config.output:
        output = SendOutputByEmail(config.output.smtp, config.input.imap)
    elif 'folder' in config.output:
        output = OutputToFolder(config.output.folder)
    else:
        raise ValueError(f"Unknown output type")

    logging.info("Running emails-html-to-pdf")

    with output:
        process_mail(
            output=output,
            imap_url=config.input.imap.server,
            imap_username=config.input.imap.username,
            imap_password=config.input.imap.password,
            imap_folder=config.input.imap.folder,
            printfailedmessage=printfailedmessage,
            pdfkit_options=config.get('conversion', {}).get('wkhtmltopdf', {}).get('options'),
            mail_msg_flag=mail_msg_flag,
            filter_criteria=filter,
        )
