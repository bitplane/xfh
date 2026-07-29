"""Public exception hierarchy."""


class XfhError(Exception):
    """Base class for expected recovery failures."""


class InvalidFormatError(XfhError):
    """The input is not a recognized XPK stream."""


class CorruptDataError(XfhError):
    """The stream is recognized but fails structural or checksum validation."""


class UnsupportedCodecError(XfhError):
    """The stream uses a codec or mode which is not implemented."""

    def __init__(self, codec: str, mode: int | None = None):
        detail = codec if mode is None else f"{codec}.{mode}"
        super().__init__(f"unsupported XPK codec: {detail}")
        self.codec = codec
        self.mode = mode


class PasswordRequiredError(XfhError):
    """The input is encrypted and needs a password."""


class IncorrectPasswordError(XfhError):
    """The supplied password cannot decrypt the input."""


class ResourceLimitError(XfhError):
    """The stream exceeds a configured recovery safety limit."""
