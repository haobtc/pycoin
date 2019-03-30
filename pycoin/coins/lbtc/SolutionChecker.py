from ...tx.script import errno
from ...tx.script import ScriptError
from ...tx.script.flags import SIGHASH_FORKID

from ...serialize.bitcoin_streamer import (
    stream_struct
)
from ..hardfork.SolutionChecker import HardforkSolutionChecker
from pycoin.serialize import h2b, b2h

class LBTCSolutionChecker(HardforkSolutionChecker):

    def append_signature(self, f):
        stream_struct('L', f, 0x4354424c)

    def signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type, **kw):
        if self.tx.ALLOW_SEGWIT:
            return self.signature_for_hash_type_segwit(tx_out_script, unsigned_txs_out_idx, hash_type)
        else:
            return self.signature_for_hash_type_plainold(tx_out_script, unsigned_txs_out_idx, hash_type)
