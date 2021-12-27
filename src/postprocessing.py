

from abc import abstractmethod
import logging


def get_post_processor(config):
    """Configures the post-processor from the provided config"""
    enabled_processors = set(config.get('POST_PROCESSORS', 'FLAG').split(','))

    processors = []
    for p in enabled_processors:
        if p.upper() == '':
            continue
        elif p.upper() == 'FLAG':
            flags = config.get("MAIL_MESSAGE_FLAG", 'SEEN').upper()
            processors.append(MailFlagPostProcessor(flags))
        elif p.upper() == 'MOVE':
            folder = config.get("MAIL_MOVE_TO_FOLDER")
            processors.append(MailMovePostProcessor(folder))
        else:
            raise ValueError(f"Unknown post-processor '{p}'")

    if len(processors) == 0:
        return StubPostProcessor()
    elif len(processors) == 1:
        return processors[0]
    else:
        return CompositePostProcessor(processors)


class PostProcessor:

    _logger = logging.getLogger(__name__)

    @abstractmethod
    def process(self, mailbox, message):
        """Perform post-processing tasks on the message"""
        pass


class CompositePostProcessor(PostProcessor):

    def __init__(self, processors):
        self.__processors = processors

    def process(self, mailbox, message):
        for p in self.__processors:
            p.process(mailbox, message)


class StubPostProcessor(PostProcessor):

    def process(self, flag, action):
        logging.debug("No post-processor configured. Skipping.")


class MailFlagPostProcessor(PostProcessor):
    """Post-processor to manipulate the IMAP flags on the message

    DRAFT flag is excluded as it can cause strange behaviour with inbound mail becoming outbound.
    RECENT flag is excluded as it is read-only
    """

    FLAG_SEEN = 'SEEN'
    FLAG_ANSWERED = 'ANSWERED'
    FLAG_FLAGGED = 'FLAGGED'
    FLAG_DELETED = 'DELETED'
    FLAG_UNFLAGGED = 'UNFLAGGED'

    SET_ACTIONS = [FLAG_SEEN, FLAG_ANSWERED, FLAG_FLAGGED, FLAG_DELETED]
    UNSET_ACTIONS = [FLAG_UNFLAGGED]

    def __init__(self, flags):
        if isinstance(flags, str):
            self.__flags = set([flags])
        else:
            self.__flags = set(flags)

    @property
    def flags(self):
        return self.__flags

    def process(self, mailbox, message):
        to_set = set([f for f in self.flags if f in self.SET_ACTIONS])
        to_unset = set([f for f in self.flags if f in self.UNSET_ACTIONS])

        if to_set:
            mailbox.flag(message.uid, to_set, True)
            logging.debug(f"Added flags '{to_set}' to message '{message.subject}'")

        if to_unset:
            mailbox.flag(message.uid, to_unset, True)
            logging.debug(f"Removed flags '{to_unset}' from message '{message.subject}'")


class MailMovePostProcessor(PostProcessor):

    def __init__(self, destination_folder):
        self.__destination_folder = destination_folder

    def process(self, mailbox, message):
        mailbox.move(message.uid, self.__destination_folder)
        logging.info(f"Moved message '{message.subject}' to folder '{self.__destination_folder}'")