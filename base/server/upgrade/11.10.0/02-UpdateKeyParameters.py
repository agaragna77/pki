# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Migrate key constraint keyParameters to allowedKeys.* (dot-separated)
# and remove keyParameters entries from on-disk CA profiles.

import logging
import os

import pki

logger = logging.getLogger(__name__)

KEY_PARAMETERS_SUFFIX = '.constraint.params.keyParameters'
MLDSA_SIZES = frozenset({'44', '65', '87'})


def classify_key_parameter_token(token):
    """
    Map a single keyParameters token to (family, value) for allowedKeys,
    where family is mldsa, rsa, or ec.
    """
    t = token.strip()
    if not t:
        return None
    if t in MLDSA_SIZES:
        return 'mldsa', t
    if t.isdigit():
        return 'rsa', t
    return 'ec', t


def _parse_property_line(line):
    """
    Return (key, value) for a single-line property, or (None, None) if not a property.
    """
    s = line.lstrip()
    if not s or s.startswith('#') or '=' not in s:
        return None, None
    key, _, rest = s.partition('=')
    key = key.rstrip()
    if not key:
        return None, None
    return key, rest.lstrip().rstrip()


def _collect_property_keys(lines):
    keys = set()
    for line in lines:
        k, _ = _parse_property_line(line)
        if k:
            keys.add(k)
    return keys


def _build_rewritten_profile_content(path):
    """
    Replace keyParameters lines with allowedKeys.* lines at the same positions;
    leave all other lines and their order unchanged.
    Returns new file content, or None if there is nothing to migrate.
    """
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    has_trailing_nl = content.endswith('\n')
    lines = content.splitlines()

    has_kp = False
    for L in lines:
        k, _ = _parse_property_line(L)
        if k and k.endswith(KEY_PARAMETERS_SUFFIX):
            has_kp = True
            break
    if not has_kp:
        return None

    all_keys = _collect_property_keys(lines)
    out = []

    for line in lines:
        k, val = _parse_property_line(line)
        if not k or not k.endswith(KEY_PARAMETERS_SUFFIX):
            out.append(line)
            continue

        lead = line[:len(line) - len(line.lstrip())]
        base = k[:-len('keyParameters')]
        value = (val or '').strip()
        if value:
            for part in value.split(','):
                classified = classify_key_parameter_token(part)
                if classified is None:
                    continue
                family, inner = classified
                ak_key = '{}allowedKeys.{}.{}'.format(base, family, inner)
                if ak_key in all_keys:
                    logger.debug(
                        '%s: skip duplicate %s (already set)',
                        os.path.basename(path),
                        ak_key,
                    )
                    continue
                out.append('{}{}=true'.format(lead, ak_key))
                all_keys.add(ak_key)
                logger.info(
                    '%s: %s -> %s=true',
                    os.path.basename(path),
                    k,
                    ak_key,
                )
        logger.info('%s: removed %s', os.path.basename(path), k)
        # drop original keyParameters line

    body = '\n'.join(out)
    if has_trailing_nl or out:
        body += '\n'
    if body == content:
        return None
    return body


class UpdateKeyParameters(pki.server.upgrade.PKIServerUpgradeScriptlet):
    """
    For each CA profile already present under the instance, move
    constraint.params.keyParameters comma-separated values into
    constraint.params.allowedKeys.<family>.<value>=true and delete the
    keyParameters property.

    NOTE: the update does not work with LDAP stored profiles (file-based
    instance profiles only), matching 04-UpdateMLDSAProfiles.py behavior.
    """

    def __init__(self):
        super().__init__()
        self.message = 'Migrate key constraint keyParameters to allowedKeys'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path_instance = os.path.join(subsystem.base_dir, 'profiles', 'ca')
        if not os.path.isdir(path_instance):
            logger.debug('No instance profile directory: %s', path_instance)
            return

        for file_name in sorted(os.listdir(path_instance)):
            if not file_name.endswith('.cfg'):
                continue

            path = os.path.join(path_instance, file_name)

            new_body = _build_rewritten_profile_content(path)
            if new_body is None:
                continue

            self.backup(path)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new_body)
            logger.info('Storing %s', path)

        logger.info('keyParameters -> allowedKeys profile update completed')
