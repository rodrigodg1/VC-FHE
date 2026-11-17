"""Stable printable-ASCII SDK invocation without copying SDK or credentials."""
import hashlib
import os
from pathlib import Path
import stat


def proxy_safe(value):
    return isinstance(value, str) and bool(value) and all(0x20 <= ord(c) < 0x7f for c in value)


def validate_python_invocation(value):
    if not proxy_safe(value):
        raise ValueError('CLOUDSDK_PYTHON must use a printable ASCII invocation path for IAP. '
                         'No interpreter, authentication or SDK setting was changed.')
    return value


def _private_alias_directory(directory):
    directory = Path(directory).absolute()
    if not proxy_safe(str(directory)):
        raise ValueError('SDK alias directory must use a printable ASCII path')
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    value = directory.lstat()
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o700):
        raise ValueError('SDK alias directory is conflicting or not private user-owned mode0700')
    return directory


def safe_sdk_invocation(sdk, *, alias_directory=None):
    """Return a logical SDK path that the pinned IAP ProxyCommand accepts.

    A directory alias preserves the SDK shell wrapper's logical lib path.
    A symlink to bin/gcloud itself would be resolved by that wrapper.
    """
    sdk = Path(sdk).absolute()
    if not sdk.is_file() or not os.access(sdk, os.X_OK):
        raise ValueError('Existing executable SDK entry point is required')
    # Preserve a functioning ASCII logical path. Ancestor symlinks are useful
    # here, but direct executable/bin symlinks are resolved by the SDK wrapper.
    if proxy_safe(str(sdk)) and not sdk.is_symlink() and not sdk.parent.is_symlink():
        return str(sdk)
    physical = sdk.resolve(strict=True)
    sdk_root = physical.parent.parent
    if (physical.name != 'gcloud' or physical.parent.name != 'bin'
            or not (sdk_root/'lib/gcloud.py').is_file()):
        raise ValueError('Cannot identify the existing SDK root without changing the installation')
    # A resolved ASCII SDK remains usable without an alias.
    if proxy_safe(str(physical)):
        return str(physical)
    directory = _private_alias_directory(alias_directory or ('/tmp/vcfhe-cloud-tools-'+str(os.getuid())))
    name = 'google-cloud-sdk-'+hashlib.sha256(str(sdk_root).encode()).hexdigest()[:16]
    alias = directory/name
    try:
        alias.symlink_to(sdk_root, target_is_directory=True)
    except FileExistsError:
        pass
    if not alias.is_symlink():
        raise ValueError('Conflicting SDK alias is preserved. Refusing replacement')
    try:
        target = alias.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError('Stale SDK alias is preserved. Refusing replacement') from error
    if target != sdk_root:
        raise ValueError('SDK alias identifies a different installation. Refusing replacement')
    logical = alias/'bin/gcloud'
    if not proxy_safe(str(logical)) or logical.resolve(strict=True) != physical:
        raise ValueError('SDK alias did not preserve the existing executable identity')
    return str(logical)
