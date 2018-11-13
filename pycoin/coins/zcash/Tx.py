from .SolutionChecker import ZCashSolutionChecker
from ..bitcoin.Solver import BitcoinSolver as ZCashSolver

from pycoin.tx.Tx import Tx as BaseTx

from pycoin.serialize.bitcoin_streamer import (parse_struct, parse_bc_int,
                                               stream_struct)


class Tx(BaseTx):
    Solver = ZCashSolver
    SolutionChecker = ZCashSolutionChecker
    ALLOW_SEGWIT = False

    def __init__(self,
                 version,
                 txs_in,
                 txs_out,
                 versiongroupid,
                 expiry_height,
                 value_balance,
                 shielded_spend,
                 shielded_output,
                 joinsplit,
                 lock_time=0,
                 unspents=None,
                 pre_block_hash=None):

        super(Tx, self).__init__(
            version, txs_in, txs_out, lock_time=0, unspents=None)
        self.pre_block_hash = pre_block_hash
        self.header = 0x80000004
        self.versiongroupid = versiongroupid
        self.lock_time = lock_time
        self.expiry_height = expiry_height
        self.value_balance = value_balance
        self.shielded_spend = shielded_spend
        self.shielded_output = shielded_output
        self.joinsplit = joinsplit

    def replace(self, **kwargs):
        new_tx = super(Tx, self).replace(**kwargs)
        new_tx.pre_block_hash = kwargs.get('pre_block_hash',
                                           self.pre_block_hash)
        return new_tx

    def stream(self,
               f,
               blank_solutions=False,
               include_unspents=False,
               include_witness_data=True):
        """Stream a Bitcoin transaction Tx to the file-like object f."""

        stream_struct("L", f, self.header)
        stream_struct("L", f, self.versiongroupid)
        stream_struct("I", f, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f, blank_solutions=blank_solutions)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        stream_struct("L", f, self.lock_time)
        stream_struct("L", f, self.expiry_height)
        stream_struct("Q", f, self.value_balance)
        stream_struct("I", f, len(self.shielded_spend))
        stream_struct("I", f, len(self.shielded_output))
        stream_struct("I", f, len(self.joinsplit))

    @classmethod
    def parse(class_, f, allow_segwit=None):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
        txs_in = []
        txs_out = []
        version, = parse_struct("L", f)
        versiongroupid, = parse_struct("L", f)

        v1 = ord(f.read(1))
        count = parse_bc_int(f, v=v1)
        txs_in = []
        for i in range(count):
            txs_in.append(class_.TxIn.parse(f))
        v2 = None
        count = parse_bc_int(f, v=v2)
        txs_out = []
        for i in range(count):
            txs_out.append(class_.TxOut.parse(f))

        lock_time, = parse_struct("L", f)
        expiry_height, = parse_struct("L", f)
        value_balance, = parse_struct("Q", f)
        count = parse_bc_int(f)
        shielded_spend = f.read(count)
        count = parse_bc_int(f)
        shielded_output = f.read(count)
        count = parse_bc_int(f)
        joinsplit = f.read(count)

        return class_(version, txs_in, txs_out, versiongroupid, expiry_height,
                      value_balance, shielded_spend, shielded_output,
                      joinsplit, lock_time)
