

from abc import abstractmethod
import logging


class PostProcessor:

    _logger = logging.getLogger(__name__)

    @abstractmethod
    def process(self, mailbox, message):
        """Perform post-processing tasks on the message"""
        pass


class SubPostProcesor(PostProcessor):

    def process(self, flag, action):
        logging.debug("No post-processor configured. Skipping.")


class MailFlagPostProcessor(PostProcessor):
    """Post-processor to manipulate the IMAP flags on the message"""

    ACTION_SET=True
    ACTION_UNSET=False

    def __init__(self, flags, action):
        self.__flags = flags
        self.__action = action

    def process(self, mailbox, message):
        mailbox.flag(message.uid, self.__flags, self.__action)
        if self.__action == self.ACTION_SET:
            logging.debug(f"Added flag '{self.__action}' to message '{message.subject}'")
        else:
            logging.debug(f"Removed flag '{self.__action}' from message '{message.subject}'")


class MailMovePostProcessor(PostProcessor):

    def __init__(self, destination_folder):
        self.__destination_folder = destination_folder

    def process(self, mailbox, message):
        mailbox.move(message.uid, self.__destination_folder)
        logging.info(f"Moved message '{message.subject}' to folder '{self.__destination_folder}'")