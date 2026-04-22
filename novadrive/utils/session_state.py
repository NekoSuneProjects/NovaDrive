from __future__ import annotations


NOVA_SESSION_KEYS = (
    "nova_session_token",
    "nova_generated_api_key",
    "nova_generated_webdav_password",
    "nova_2fa_user_id",
    "nova_2fa_remember",
    "nova_2fa_next",
)


def clear_novadrive_session_state(session_obj) -> None:
    for key in NOVA_SESSION_KEYS:
        session_obj.pop(key, None)
