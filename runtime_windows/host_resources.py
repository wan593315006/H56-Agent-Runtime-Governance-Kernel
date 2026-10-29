"""Prepared exact-resource readback and owned-session lock; never provisioning.

All native binding is explicit and behind an externally pinned host permit.
Matching metadata is not proof of network/file isolation. Accepted negative
experiments remain a separate Controller prerequisite. No function here sets an
ACL, creates/deletes a Profile, enables a privilege or enumerates resources.
"""
import hashlib
import ntpath
import re
from pathlib import Path

from .host_contract import (digest, fail, require_host_permit, validate_resource_contract,
                            windows_path)


def validate_readonly_sddl(sddl, host_sid, app_sid):
    """Conservative supported ACE subset for a newly copied receipt.

    This is a reject-on-unknown descriptor check, not AccessCheck or evidence of
    effective denial. Complex/object/callback ACEs and non-read generic grants
    are deliberately unsupported; they require a new reviewed contract.
    """
    if type(sddl) is not str or not 1 <= len(sddl) <= 65536:
        fail('HOST_RECEIPT_DACL_UNVERIFIED')
    match = re.fullmatch(r'O:([^:]+)G:([^:]+)D:(.*?)(S:.*)?', sddl)
    if not match or match[1] not in (host_sid, 'SY'):
        fail('HOST_RECEIPT_OWNER_UNVERIFIED')
    dacl, sacl = match[3], match[4] or ''
    aces = re.findall(r'\(([^()]*)\)', dacl)
    if not aces or re.sub(r'\([^()]*\)', '', dacl) not in ('', 'P', 'AI', 'PAI', 'AR', 'PAR'):
        fail('HOST_RECEIPT_DACL_UNSUPPORTED')
    app_read = False
    # READ_CONTROL/SYNCHRONIZE + FILE_READ_DATA/EA/ATTR only.
    readonly_mask = 0x00120089
    aliases = {'FR': 0x00120089, 'GR': 0x80000000, 'FA': 0x001F01FF,
               'GA': 0x10000000, 'FW': 0x00120116, 'GW': 0x40000000,
               'FX': 0x001200A0, 'GX': 0x20000000}
    for ace in aces:
        fields = ace.split(';')
        if len(fields) != 6 or fields[0] not in ('A', 'D') or fields[3:5] != ['', '']:
            fail('HOST_RECEIPT_DACL_UNSUPPORTED')
        kind, flags, rights, _, _, sid = fields
        if any(value not in ('OI', 'CI', 'IO', 'ID', 'NP') for value in re.findall('..', flags)) or len(flags) % 2:
            fail('HOST_RECEIPT_DACL_UNSUPPORTED')
        try:
            mask = int(rights, 16) if re.fullmatch(r'0x[0-9a-fA-F]{1,8}', rights) else aliases[rights]
        except (ValueError, KeyError):
            fail('HOST_RECEIPT_DACL_RIGHTS_UNKNOWN')
        if kind == 'A' and 'IO' not in flags and sid not in (host_sid, 'SY'):
            if mask & ~readonly_mask:
                fail('HOST_RECEIPT_NONHOST_WRITE_OR_UNKNOWN_GRANT')
            if sid == app_sid and mask & 1:
                app_read = True
    # Mandatory-label inheritance may set ID on the copied file. No other
    # inheritance/mask/level form is accepted without a reviewed extension.
    if not app_read or not re.fullmatch(r'S:\(ML;(?:ID)?;NW;;;LW\)', sacl):
        fail('HOST_RECEIPT_READ_OR_LABEL_UNVERIFIED')


class ResourceReadback:
    """Concrete native verifier for only the declared resource objects."""
    def __init__(self, resources, permit):
        validate_resource_contract(resources)
        require_host_permit(permit, 'RESOURCE_INSPECTION', digest(resources))
        import os
        if os.name != 'nt':
            fail('HOST_WINDOWS_REQUIRED')
        import ctypes as ct
        if ct.sizeof(ct.c_void_p) != 8:
            fail('HOST_RESOURCE_ABI_UNSUPPORTED')
        self.ct, self.resources = ct, resources
        D, H, W, P = ct.c_uint32, ct.c_void_p, ct.c_wchar_p, ct.POINTER
        self.D, self.H = D, H
        kernel = ct.WinDLL('kernel32.dll', use_last_error=True)
        security = ct.WinDLL('advapi32.dll', use_last_error=True)
        userenv = ct.WinDLL('userenv.dll', use_last_error=True)
        ole = ct.WinDLL('ole32.dll', use_last_error=True)
        self.api = {}
        def bind(dll, name, args, restype):
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = args, restype
            self.api[name] = fn
        bind(kernel, 'CreateFileW', [W, D, D, H, D, D, H], H)
        bind(kernel, 'CloseHandle', [H], ct.c_int)
        bind(kernel, 'GetFinalPathNameByHandleW', [H, W, D, D], D)
        bind(kernel, 'GetFileInformationByHandle', [H, H], ct.c_int)
        bind(kernel, 'LocalFree', [H], H)
        bind(security, 'GetSecurityInfo', [H, ct.c_int, D, H, H, H, H, P(H)], D)
        bind(security, 'ConvertSecurityDescriptorToStringSecurityDescriptorW', [H, D, D, P(H), P(D)], ct.c_int)
        bind(security, 'ConvertSidToStringSidW', [H, P(H)], ct.c_int)
        bind(security, 'FreeSid', [H], H)
        bind(security, 'RegOpenKeyExW', [H, W, D, D, P(H)], ct.c_int32)
        bind(security, 'RegCloseKey', [H], ct.c_int32)
        bind(userenv, 'DeriveAppContainerSidFromAppContainerName', [W, P(H)], ct.c_int32)
        bind(userenv, 'GetAppContainerFolderPath', [W, P(H)], ct.c_int32)
        bind(ole, 'CoTaskMemFree', [H], None)

    def _error(self, code):
        fail(code, str(self.ct.get_last_error()))

    def _close(self, handle):
        if not self.api['CloseHandle'](handle):
            self._error('HOST_RESOURCE_HANDLE_CLOSE_FAILED')

    def _security(self, handle, object_type):
        ct, descriptor, text, count = self.ct, self.H(), self.H(), self.D()
        # OWNER/GROUP/DACL/LABEL, not arbitrary whole SACL; no privilege enable.
        code = self.api['GetSecurityInfo'](handle, object_type, 0x17, None, None, None, None, ct.byref(descriptor))
        if code:
            fail('HOST_RESOURCE_SECURITY_READ_FAILED', str(code))
        primary, value, cleanup = None, None, []
        try:
            if not self.api['ConvertSecurityDescriptorToStringSecurityDescriptorW'](
                    descriptor, 1, 0x17, ct.byref(text), ct.byref(count)):
                self._error('HOST_RESOURCE_SDDL_CONVERSION_FAILED')
            if not 1 <= count.value <= 65536:
                fail('HOST_RESOURCE_SDDL_BUDGET')
            # API returns buffer capacity, not necessarily string length. Its
            # trusted NUL terminator bounds the string, then capacity is checked.
            value = ct.wstring_at(text.value)
            if len(value) + 1 > count.value or len(value) > 65535:
                fail('HOST_RESOURCE_SDDL_RETURN_LENGTH')
        except Exception as error:
            primary = error
        finally:
            if text.value and self.api['LocalFree'](text.value):
                cleanup.append('HOST_RESOURCE_SDDL_FREE_FAILED')
            if descriptor.value and self.api['LocalFree'](descriptor.value):
                cleanup.append('HOST_RESOURCE_DESCRIPTOR_FREE_FAILED')
        if primary is not None:
            if cleanup:
                primary.args += ('cleanup=' + ','.join(cleanup),)
            raise primary
        if cleanup:
            fail('HOST_RESOURCE_SECURITY_CLEANUP_NOT_VERIFIED', ','.join(cleanup))
        return value

    def file_descriptor(self, path, kind):
        """Handle-bound security and final identity, never pathname extraction."""
        from .source_identity import _check_chain
        windows_path(path)
        _check_chain(Path(path), include_leaf=(kind == 'directory'))
        handle = self.api['CreateFileW'](path, 0x00020080, 1, None, 3,
            0x00200000 | (0x02000000 if kind == 'directory' else 0), None)
        if not handle or handle == self.H(-1).value:
            self._error('HOST_RESOURCE_OPEN_FAILED')
        try:
            # BY_HANDLE_FILE_INFORMATION: 52B; reject reparse and file hardlinks.
            info = self.ct.create_string_buffer(52)
            if not self.api['GetFileInformationByHandle'](handle, info):
                self._error('HOST_RESOURCE_FILE_ID_FAILED')
            attributes = int.from_bytes(info.raw[:4], 'little')
            links = int.from_bytes(info.raw[40:44], 'little')
            if attributes & 0x400 or bool(attributes & 0x10) != (kind == 'directory') or (kind == 'file' and links != 1):
                fail('HOST_RESOURCE_REPARSE_TYPE_OR_LINKS')
            final = self.ct.create_unicode_buffer(512)
            size = self.api['GetFinalPathNameByHandleW'](handle, final, len(final), 0)
            if not 1 <= size < len(final):
                fail('HOST_RESOURCE_FINAL_PATH_BUDGET')
            actual = final.value
            if actual.startswith('\\\\?\\'):
                actual = actual[4:]
            if windows_path(actual) != windows_path(path):
                fail('HOST_RESOURCE_FINAL_PATH_MISMATCH')
            before = bytes(info)
            sddl = self._security(handle, 1)
            if not self.api['GetFileInformationByHandle'](handle, info) or bytes(info) != before:
                fail('HOST_RESOURCE_FILE_CHANGED_DURING_SECURITY_READ')
            return sddl
        finally:
            self._close(handle)

    def verify(self):
        ct, profile = self.ct, self.resources['profile']
        # The only process-token query is the current trusted operator process.
        from .kernel_probe import _bind_windows_api, _decode_sid_bytes
        _, queries, _ = _bind_windows_api()
        handle, needed = self.H(), self.D()
        if not queries['open_process_token'](queries['current_process'](), 8, ct.byref(handle)):
            fail('HOST_CURRENT_OWNER_TOKEN_QUERY_FAILED')
        try:
            ct.set_last_error(0)
            if queries['token_info'](handle, 1, None, 0, ct.byref(needed)) or ct.get_last_error() != 122 or not 16 <= needed.value <= 65536:
                fail('HOST_CURRENT_OWNER_TOKEN_BUDGET')
            buffer, returned = ct.create_string_buffer(needed.value), self.D()
            if not queries['token_info'](handle, 1, buffer, len(buffer), ct.byref(returned)) or not 16 <= returned.value <= len(buffer):
                fail('HOST_CURRENT_OWNER_TOKEN_READ_FAILED')
            pointer = self.H.from_buffer_copy(buffer.raw[:8]).value
            offset = (pointer or 0) - ct.addressof(buffer)
            if offset < 0 or offset + 8 > returned.value:
                fail('HOST_CURRENT_OWNER_TOKEN_SID_BOUNDS')
            size = 8 + 4 * buffer.raw[offset + 1]
            if offset + size > returned.value or _decode_sid_bytes(buffer.raw[offset:offset+size]) != self.resources['host_user_sid']:
                fail('HOST_CURRENT_OWNER_SID_MISMATCH')
        finally:
            self._close(handle)
        sid, text, folder = self.H(), self.H(), self.H()
        if self.api['DeriveAppContainerSidFromAppContainerName'](profile['name'], ct.byref(sid)) != 0:
            fail('HOST_PROFILE_DERIVATION_FAILED')
        primary, cleanup = None, []
        try:
            if not self.api['ConvertSidToStringSidW'](sid, ct.byref(text)):
                self._error('HOST_PROFILE_SID_CONVERSION_FAILED')
            actual_sid = ct.wstring_at(text.value)
            if len(actual_sid) > 184 or actual_sid != profile['sid']:
                fail('HOST_PROFILE_DERIVED_SID_MISMATCH')
        except Exception as error:
            primary = error
        finally:
            if text.value:
                if self.api['LocalFree'](text.value):
                    cleanup.append('HOST_PROFILE_SID_TEXT_FREE_FAILED')
            if sid.value:
                if self.api['FreeSid'](sid.value):
                    cleanup.append('HOST_PROFILE_SID_FREE_FAILED')
        if primary is not None:
            if cleanup:
                primary.args += ('cleanup=' + ','.join(cleanup),)
            raise primary
        if cleanup:
            fail('HOST_PROFILE_SID_CLEANUP_NOT_VERIFIED', ','.join(cleanup))
        if self.api['GetAppContainerFolderPath'](profile['sid'], ct.byref(folder)) != 0:
            fail('HOST_PREEXISTING_PROFILE_STORAGE_REQUIRED')
        try:
            actual = ct.wstring_at(folder.value)
            if len(actual) > 240:
                fail('HOST_PROFILE_STORAGE_PATH_BUDGET')
            if windows_path(actual) != windows_path(profile['storage_root']):
                fail('HOST_PROFILE_STORAGE_MISMATCH')
        finally:
            if folder.value:
                self.api['CoTaskMemFree'](folder.value)
        observations = []
        for item in self.resources['acl_objects']:
            sddl = self.file_descriptor(item['path'], item['kind'])
            observed = hashlib.sha256(sddl.encode('utf-8')).hexdigest()
            if observed != item['sddl_sha256']:
                fail('HOST_RESOURCE_ACL_DRIFT')
            observations.append(dict(path=item['path'], sddl_sha256=observed))
        for item in self.resources['registry_objects']:
            handle = self.H()
            # HKCU exact approved profile subkeys only; no enumeration.
            code = self.api['RegOpenKeyExW'](self.H(0xFFFFFFFF80000001), item['subkey'], 0, 0x00020019, ct.byref(handle))
            if code:
                fail('HOST_PROFILE_REGISTRY_READ_FAILED', str(code))
            try:
                sddl = self._security(handle, 4)
                if hashlib.sha256(sddl.encode('utf-8')).hexdigest() != item['sddl_sha256']:
                    fail('HOST_PROFILE_REGISTRY_ACL_DRIFT')
            finally:
                if self.api['RegCloseKey'](handle):
                    fail('HOST_PROFILE_REGISTRY_CLOSE_FAILED')
        return dict(status='DECLARED_METADATA_MATCH_NOT_ISOLATION_ACCEPTANCE', objects=observations)

    def verify_receipt_readonly(self, path):
        root = self.resources['paths']['receipt_input_root']
        relative = ntpath.relpath(str(path), root)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}\\receipt\.json', relative):
            fail('HOST_RECEIPT_COPY_OUTSIDE_DECLARED_ROOT')
        descriptor = self.file_descriptor(str(path), 'file')
        validate_readonly_sddl(descriptor, self.resources['host_user_sid'], self.resources['profile']['sid'])
        return hashlib.sha256(descriptor.encode('utf-8')).hexdigest()

    def active_lock(self, permit):
        require_host_permit(permit, 'SESSION_CONTROL', digest(self.resources))
        return _ActiveLock(self)


class _ActiveLock:
    def __init__(self, verifier):
        self.verifier, self.handle = verifier, None

    def __enter__(self):
        # CREATE_NEW, no sharing, DELETE_ON_CLOSE. Only this declared lock file.
        path = self.verifier.resources['paths']['active_lock_path']
        self.handle = self.verifier.api['CreateFileW'](path, 0x00110003, 0, None, 1, 0x04000100, None)
        if not self.handle or self.handle == self.verifier.H(-1).value:
            self.verifier._error('HOST_SESSION_ALREADY_ACTIVE_OR_LOCK_DENIED')
        return self

    def __exit__(self, typ, value, traceback):
        self.verifier._close(self.handle)
