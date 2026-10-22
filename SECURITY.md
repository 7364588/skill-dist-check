# Security

This tool reads explicitly supplied directories and ZIP files. It does not run
skill code, extract archives, install skills or scan home directories. Checks
have bounded file counts and sizes; see the README. Hashes detect differences,
not authorship or trust. A correctly hashed bundle can contain harmful content.

Report a vulnerability through the repository's private vulnerability reporting
feature when available. Avoid putting sensitive payloads in public issues. For
ordinary defects, use a small synthetic reproduction.
