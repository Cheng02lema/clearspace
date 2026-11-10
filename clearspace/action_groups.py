"""Page and column placement for the actions exposed by the legacy core."""

ACTION_GROUPS = {
    'mail-cookie': ('browser', 'settings'),
    'block-location': ('browser', 'settings'),
    'block-location-sync-language': ('browser', 'settings'),
    'restore-browser-location-language': ('browser', 'restore'),
    'restrict-webrtc': ('browser', 'settings'),
    'install-adguard': ('browser', 'settings'),
    'remove-managed-adguard': ('browser', 'restore'),
    'claude-environment': ('system', 'settings'),
    'disable-system-location': ('system', 'settings'),
    'protect-dns': ('system', 'settings'),
    'restore-dns': ('system', 'restore'),
    'sync-proxy-timezone': ('system', 'settings'),
    'restore-china-timezone': ('system', 'restore'),
}


def action_group(action):
    return ACTION_GROUPS.get(action['id'], ('system', 'settings'))
