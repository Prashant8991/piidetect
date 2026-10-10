"""Common interface every file format implements."""


class Handler:
    exts = ()                 # file extensions handled, e.g. (".pdf",)
    verify_by_default = True  # run the post-redaction leak check by default?

    def __init__(self, path, workers=None, cache=False):
        self.path, self.workers, self.cache = path, workers, cache
        self.warnings = []    # things the handler could not process (reported in the log)

    def extract(self):
        """Read the file and return a list of Unit objects (text + the data needed to redact later)."""
        raise NotImplementedError

    def redact(self, units, out_path, tokens, fail_closed=False):
        """Apply unit.keep spans to the file and save it to out_path."""
        raise NotImplementedError
