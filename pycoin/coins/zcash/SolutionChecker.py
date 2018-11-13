import io

from ..bitcoin.SolutionChecker import BitcoinSolutionChecker
from hashlib import blake2b
from ...encoding import from_bytes_32
from ...serialize.bitcoin_streamer import (stream_struct, stream_bc_string)

from ...tx.script.flags import (SIGHASH_NONE, SIGHASH_SINGLE,
                                SIGHASH_ANYONECANPAY)

ZERO32 = b'\0' * 32

ZCASH_PREVOUTS_HASH_PERSONALIZATION = b'ZcashPrevoutHash'
ZCASH_SEQUENCE_HASH_PERSONALIZATION = b'ZcashSequencHash'
ZCASH_OUTPUTS_HASH_PERSONALIZATION = b'ZcashOutputsHash'
ZCASH_JOINSPLITS_HASH_PERSONALIZATION = b'ZcashJSplitsHash'
ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION = b'ZcashSSpendsHash'
ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION = b'ZcashSOutputHash'
ZCASH_SIG_HASH_PERSONALIZATION = bytes.fromhex(
    '5a6361736853696748617368bb09b876')


class ZCashSolutionChecker(BitcoinSolutionChecker):
    def hash_prevouts(self, hash_type):
        if hash_type & SIGHASH_ANYONECANPAY:
            return ZERO32
        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return blake2b(
            f.getvalue(),
            digest_size=32,
            person=ZCASH_PREVOUTS_HASH_PERSONALIZATION).digest()

    def hash_sequence(self, hash_type):
        if ((hash_type & SIGHASH_ANYONECANPAY)
                or ((hash_type & 0x1f) == SIGHASH_SINGLE)
                or ((hash_type & 0x1f) == SIGHASH_NONE)):
            return ZERO32

        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            stream_struct("L", f, tx_in.sequence)
        return blake2b(
            f.getvalue(),
            digest_size=32,
            person=ZCASH_SEQUENCE_HASH_PERSONALIZATION).digest()

    def hash_outputs(self, hash_type, tx_in_idx):
        txs_out = self.tx.txs_out
        if hash_type & 0x1f == SIGHASH_SINGLE:
            if tx_in_idx >= len(txs_out):
                return ZERO32
            txs_out = txs_out[tx_in_idx:tx_in_idx + 1]
        elif hash_type & 0x1f == SIGHASH_NONE:
            return ZERO32
        f = io.BytesIO()
        for tx_out in txs_out:
            stream_struct("Q", f, tx_out.coin_value)
            self.ScriptTools.write_push_data([tx_out.script], f)
        return blake2b(
            f.getvalue(),
            digest_size=32,
            person=ZCASH_OUTPUTS_HASH_PERSONALIZATION).digest()

    def signature_preimage(self, script, tx_in_idx, hash_type=None):
        f = io.BytesIO()
        stream_struct("L", f, self.tx.header)
        stream_struct("L", f, self.tx.versiongroupid)

        # calculate hash prevouts
        f.write(self.hash_prevouts(hash_type))
        f.write(self.hash_sequence(hash_type))
        f.write(self.hash_outputs(hash_type, tx_in_idx))

        f.write(bytes([0] * 32))  # hashJoinSplits
        f.write(bytes([0] * 32))  # hashShieldedSpends
        f.write(bytes([0] * 32))  # hashShieldedOutputs

        stream_struct("L", f, self.tx.lock_time)
        stream_struct("L", f, self.tx.expiry_height)
        stream_struct("Q", f, self.tx.value_balance)

        stream_struct("L", f, hash_type)

        tx_in = self.tx.txs_in[tx_in_idx]
        f.write(tx_in.previous_hash)
        stream_struct("L", f, tx_in.previous_index)

        stream_bc_string(f, script)
        tx_out = self.tx.unspents[tx_in_idx]
        stream_struct("Q", f, tx_out.coin_value)
        stream_struct("L", f, tx_in.sequence)
        return f.getvalue()

    def signature_for_hash_type(self, script, tx_in_idx, hash_type):
        return from_bytes_32(
            blake2b(
                self.signature_preimage(script, tx_in_idx, hash_type),
                digest_size=32,
                person=ZCASH_SIG_HASH_PERSONALIZATION).digest())

    def signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
        """
        Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        tx_out_script: the script the coins for unsigned_txs_out_idx are
        coming from unsigned_txs_out_idx: where to put the tx_out_script
        hash_type: one of SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL,
        optionally bitwise or'ed with SIGHASH_ANYONECANPAY
        """
        return self.signature_for_hash_type(tx_out_script,
                                            unsigned_txs_out_idx, hash_type)
