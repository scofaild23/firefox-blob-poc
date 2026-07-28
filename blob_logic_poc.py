#!/usr/bin/env python3
"""
LOGIC DEMONSTRATION — NOT AN EXPLOIT.

Faithfully reproduces the three access-control checks that guard blob-URL data in
Firefox, and shows that all three are satisfied by values a compromised content
process fully controls.

This does NOT send IPC and does NOT prove reachability; the IPC path is argued from
source in the accompanying report. What it does show is that the *authorisation
logic itself* grants access when the caller supplies the values below.

Transcribed verbatim from:
  dom/ipc/ContentParent.cpp:7500              ContentParent::RecvBlobURLDataRequest
  dom/file/uri/BlobURLProtocolHandler.cpp:773 BlobURLProtocolHandler::GetDataEntry
  dom/ipc/PermissionMessageUtils.cpp:27       ParamTraits<nsIPrincipal*>::Read

Run:  python3 blob_logic_poc.py
"""


class Principal:
    """Minimal stand-in for nsIPrincipal."""

    def __init__(self, origin, kind='content', origin_attributes=None):
        self.origin = origin
        self.kind = kind                                  # content | system | null | expanded
        self.origin_attributes = origin_attributes or {}

    def is_system(self):
        return self.kind == 'system'

    def subsumes(self, other):
        # nsIPrincipal::Subsumes — the system principal subsumes everything;
        # otherwise same-origin.
        if self.is_system():
            return True
        return self.origin == other.origin


class BlobEntry:
    """A DataInfo row in gDataTable — the victim's blob."""

    def __init__(self, url, owner, partition_key):
        self.url = url
        self.principal = owner
        self.partition_key = partition_key


def get_data_entry(uri, loading_principal, triggering_principal,
                   origin_attributes, partition_key, table,
                   partition_pref_enabled=True, log=print):
    """BlobURLProtocolHandler::GetDataEntry — the three checks, in order."""
    info = table.get(uri)
    if not info:
        log('   entry not found')
        return None

    # check 1 — OriginAttributes must match, UNLESS the loading principal is system
    if (not loading_principal or not loading_principal.is_system()):
        if origin_attributes != info.principal.origin_attributes:
            log('   [1] BLOCKED  OriginAttributes mismatch')
            return None
        log('   [1] passed   OriginAttributes matched')
    else:
        log('   [1] SKIPPED  loading principal claims SYSTEM -> whole check short-circuited')

    # check 2 — the triggering principal must subsume the blob owner
    if not triggering_principal.subsumes(info.principal):
        log('   [2] BLOCKED  Subsumes() false')
        return None
    log(f'   [2] passed   Subsumes() true '
        f'({"system subsumes everything" if triggering_principal.is_system() else "same origin"})')

    # check 3 — partition keys must match, but ONLY if both are non-empty
    if (partition_pref_enabled and partition_key and info.partition_key
            and partition_key != info.partition_key):
        log('   [3] BLOCKED  partition key mismatch')
        return None
    if partition_pref_enabled and not partition_key:
        log('   [3] SKIPPED  empty partition key -> condition collapses')
    else:
        log('   [3] passed')

    return info


def main():
    victim = Principal('https://bank.example', origin_attributes={'privateBrowsingId': 0})
    table = {'blob:https://bank.example/secret-uuid':
             BlobEntry('blob:https://bank.example/secret-uuid', victim, 'bank.example')}

    attacker = Principal('https://evil.example', origin_attributes={'privateBrowsingId': 0})
    system = Principal('', kind='system')

    print(__doc__.strip())
    print('\nVictim blob : blob:https://bank.example/secret-uuid  (owner https://bank.example)')
    print('Attacker    : a compromised content process hosting https://evil.example\n')

    print('=' * 72)
    print('CONTROL — attacker asks honestly, as itself')
    print('=' * 72)
    got = get_data_entry('blob:https://bank.example/secret-uuid',
                         loading_principal=attacker, triggering_principal=attacker,
                         origin_attributes=attacker.origin_attributes,
                         partition_key='evil.example', table=table)
    print(f'   RESULT: {"DATA RETURNED" if got else "denied"}\n')

    print('=' * 72)
    print('ATTACK — the same request with values the caller simply chooses')
    print('   aLoadingPrincipal    = SystemPrincipal')
    print('   aTriggeringPrincipal = SystemPrincipal')
    print('   aPartitionKey        = ""')
    print('=' * 72)
    got = get_data_entry('blob:https://bank.example/secret-uuid',
                         loading_principal=system, triggering_principal=system,
                         origin_attributes={}, partition_key='', table=table)
    print(f'   RESULT: {"DATA RETURNED  <<< all three controls bypassed" if got else "denied"}')

    if got:
        print(f'\n   attacker now holds the BlobImpl owned by {got.principal.origin}')
        print('   -> ContentParent then serialises it back over IPC (ContentParent.cpp:7517)')

    print('\n' + '=' * 72)
    print('Why the caller can choose those values:')
    print('  ParamTraits<nsIPrincipal*>::Read (PermissionMessageUtils.cpp:27) rebuilds')
    print('  whatever PrincipalInfo the sender encoded and performs NO sender check;')
    print('  RecvBlobURLDataRequest never calls ContentParent::ValidatePrincipal,')
    print('  which ~9 sibling handlers in the same file do call.')
    print('=' * 72)


if __name__ == '__main__':
    main()
