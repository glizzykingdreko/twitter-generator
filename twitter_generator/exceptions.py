class TwitterGeneratorException(Exception):
    pass

class InvalidHomePageError(TwitterGeneratorException):
    pass

class InvalidOndemandFileError(TwitterGeneratorException):
    pass

class InvalidGuestIdError(TwitterGeneratorException):
    pass
