"""Review-only, read-only SA disappearance polling after confirmed deletion.

Call only after an exact service-account delete returned success. The callback
must perform authenticated, scope-bound reads and propagate permission errors.
This helper never deletes or retries deletion. Existing transport timeouts still
apply to each read, while the polling window is bounded to at most 45 seconds.
"""
import time


def confirm_absence(config, row, require_live, *, timeout_seconds=45,
                    interval_seconds=2, clock=time.monotonic, pause=time.sleep):
    if (row.get('type') != 'google_service_account'
            or not str(row.get('identity', {}).get('uniqueId', '')).isdecimal()
            or not row.get('attributes', {}).get('email')):
        raise ValueError('A complete original service-account identity is required')
    if not 0 < timeout_seconds <= 45 or not 0 < interval_seconds <= 2:
        raise ValueError('Polling bounds must remain at most 45 seconds and 2-second intervals')
    expected_id = str(row['identity']['uniqueId'])
    expected_email = row['attributes']['email']
    deadline = clock() + timeout_seconds
    attempts = 0
    while True:
        if clock() > deadline:
            raise TimeoutError('Service-account absence was not confirmed within the polling window')
        live = require_live(config, row)
        attempts += 1
        if clock() > deadline:
            raise TimeoutError('Service-account read completed after the polling window')
        if live is None:
            return {'status': 'absent', 'attempts': attempts, 'deletionRetried': False}
        if str(live.get('uniqueId')) != expected_id or live.get('email') != expected_email:
            raise ValueError('Service-account identity changed. Refusing any further mutation')
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError('Original service account remains visible after successful delete')
        pause(min(interval_seconds, remaining))
