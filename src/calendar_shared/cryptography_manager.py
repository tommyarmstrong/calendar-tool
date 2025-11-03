from cryptography.fernet import Fernet


def get_fernet(encryption_key: bytes) -> Fernet:
    """
    Create a Fernet cipher using the configured encryption key.

    Returns:
        Fernet: Configured Fernet instance.

    Raises:
        ValueError: If the encryption key is not configured.
    """
    if not encryption_key:
        raise ValueError("Token encryption key is not configured")
    return Fernet(encryption_key)
