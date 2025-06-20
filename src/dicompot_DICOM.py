import sys

from func_timeout import func_set_timeout
from pydicom.dataset import Dataset
from pynetdicom import AE, evt
from pynetdicom.sop_class import Verification, ModalityWorklistInformationFind

PORT            = 11112
MY_AE_TITLE     = b'MYSCU'
REMOTE_AE_TITLE = b'MYSCP'

UID_SIGNATURES = {
    '1.2.840.10008.1.1': 'Verification SOP Class',
    'dicompot':         'Dicompot default Implementation Version',
    'storescp':         'Typical SCP Title',
}
C_FIND_SIG_CODES = {
    0xC000: "C-FIND UnableToProcess",
}

_impl_info = {'uid': '', 'ver': ''}

def _on_assoc_accepted(event):
    """Catch the A-ASSOCIATE-AC PDU and extract impl info."""
    primitive = event.acse.primitive
    params    = primitive.parameters
    _impl_info['uid'] = getattr(params, 'implementation_class_uid', '') or ''
    _impl_info['ver'] = getattr(params, 'implementation_version_name', '') or ''

def do_echo(host):
    """C-ECHO to fingerprint SOP UIDs + implementation info."""
    ae = AE(ae_title=MY_AE_TITLE)
    ae.add_requested_context(Verification)
    handlers = [(evt.EVT_ACCEPTED, _on_assoc_accepted)]
    assoc = ae.associate(host, PORT, ae_title=REMOTE_AE_TITLE, evt_handlers=handlers)
    if not assoc.is_established:
        return False

    values = []
    for ctx in assoc.accepted_contexts:
        values.append(str(ctx.abstract_syntax).lower())

    values += [_impl_info['uid'].lower(), _impl_info['ver'].lower()]

    assoc.release()

    fingerprint = " ".join(values)
    for sig in UID_SIGNATURES:
        if sig in fingerprint:
            return True
    return False

def do_cfind(host):
    """C-FIND (ModalityWorklist) to catch custom Status codes."""
    ae = AE(ae_title=MY_AE_TITLE)
    ae.add_requested_context(ModalityWorklistInformationFind)
    assoc = ae.associate(host, PORT)
    if not assoc.is_established:
        return False

    ds = Dataset()
    for status, _ in assoc.send_c_find(ds, ModalityWorklistInformationFind):
        code = getattr(status, 'Status', None)
        assoc.release()
        return code in C_FIND_SIG_CODES

    assoc.release()
    return False

@func_set_timeout(10)
def test(address):
    """
    Tests whether the given host behaves like a Dicompot honeypot.
    :param address: IP or hostname
    :return: True if any signature found, False otherwise
    """
    if do_echo(address):
        return True
    # if do_cfind(address):
    #     return True
    return False

