from .network import Network
from .legacy_networks import NETWORKS

from pycoin.tx.Tx import (
    Tx as BitcoinTx,
    LegacyTx as LegacyBitcoinTx
)

from pycoin.block import Block as BitcoinBlock

from pycoin.coins.bcash.Tx import Tx as BCashTx
from pycoin.coins.btg.Tx import Tx as BTGTx
from pycoin.coins.sbtc.Tx import Tx as SBTCTx
from pycoin.coins.ubtc.Tx import Tx as UBTCTx
from pycoin.coins.bcx.Tx import Tx as BCXTx
from pycoin.coins.bcd.Tx import Tx as BCDTx
from pycoin.coins.lbtc.Tx import Tx as LBTCTx

from ..serialize import h2b

BUILT_IN_NETWORKS = [

    # BTC bitcoin mainnet : xprv/xpub
    Network(
        'BTC', "Bitcoin", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        BitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ],
        bech32_hrp='bc'
    ),

    # BTC bitcoin testnet : tprv/tpub
    Network(
        "XTN", "Bitcoin", "testnet3",
        b'\xef', b'\x6f', b'\xc4', h2b("04358394"), h2b("043587CF"),
        BitcoinTx, BitcoinBlock,
        h2b('0B110907'), 18333, [
            "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
            "bluematt.me", "testnet-seed.bluematt.me"
        ],
        bech32_hrp='tb'
    ),

    # BTC bitcoin regtest : tprv/tpub
    Network(
        'XRT', "Bitcoin", "regtest",
        b'\xef', b'\x6f', b'\xc4', h2b("04358394"), h2b("043587CF"),
        BitcoinTx, BitcoinBlock,
        h2b('FABFB5DA'), 18444, [],
        bech32_hrp='bcrt'
    ),

    # LTC litecoin mainnet : Ltpv/Ltub
    Network(
        "LTC", "Litecoin", "mainnet",
        b'\xb0', b'\x30', b'\5',
        h2b('019d9cfe'), h2b('019da462'),
        tx=LegacyBitcoinTx, block=BitcoinBlock,
        bech32_hrp='lc'
    ),

    # LTC litecoin testnet : ttpv/ttub
    Network(
        "XLT", "Litecoin", "testnet",
        b'\xef', b'\x6f', b'\xc4',
        h2b('0436ef7d'), h2b('0436f6e1'),
        tx=LegacyBitcoinTx, block=BitcoinBlock,
        bech32_hrp='tl'
    ),

    # BCH bcash mainnet : xprv/xpub
    Network(
        'BCH', "Bcash", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        BCashTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
            "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
        ],
        cash_hrp='bitcoincash'
    ),

    # BTCGPU mainnet
    Network(
        'BTG', 'BTCGPU', 'mainnet',
        b'\x80', b'\x26', b'\x17', h2b("0488ADE4"), h2b("0488B21E"),   # 'G', 'A'
        BTGTx, BitcoinBlock,
        h2b('E1476D44'), 8338, [
            "eu-dnsseed.bitcoingold-official.org",
            "dnsseed.bitcoingold.org",
            "dnsseed.btcgpu.org"
        ]
    ),

    # SBTC mainnet
    Network(
        'SBTC', 'SuperBitcoin', 'mainnet',
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        SBTCTx, BitcoinBlock,
        h2b('E1476D44'), 8338, [
            "seed.superbtca.com",
            "seed.superbtca.info",
            "seed.superbtc.org",
        ]
    ),

    # SBTC mainnet
    Network(
        'UBTC', 'SuperBitcoin', 'mainnet',
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        UBTCTx, BitcoinBlock,
        h2b('E1476D44'), 8333, [
            "ip.ub.com",
        ]
    ),

    # BCX mainnet
    Network(
        'BCX', 'BitcoinX', 'mainnet',
        b'\x80', b'\x4b', b'\x3f', h2b("0488ADE4"), h2b("0488B21E"),
        BCXTx, BitcoinBlock,
        h2b('E1476D44'), 9005, [
            "seed.bcx.org",
            "seed.bcx.info"
        ]
    ),

    # BCD bitcoin diamond mainnet
    Network(
        'BCD', "BitcoinDiamond", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        BCDTx, BitcoinBlock,
        h2b('BDDEB4D9'), 7117, [
            'dns1.btcd.io', 'dns2.btcd.io',
            'dns3.btcd.io', 'dns4.btcd.io',
            'dns5.btcd.io', 'dns6.btcd.io',
        ]
    ),

    # BTX BitCore mainnet
    Network(
        'BTX', 'BitCore', 'mainnet',
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        LegacyBitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8555, [
            "dnsseed1.bitcore.org", "dnsseed2.bitcore.org",
        ]
    ),

    # ULORD mainnet
    Network(
        'UT', 'UlordChain', 'mainnet',
        b'\x80', b'\x44', b'\x3f', h2b("0488ADE4"), h2b("0488B21E"),
        LegacyBitcoinTx, BitcoinBlock,
        h2b('E1476D44'), 9888, [
            "dnsseed1.ulord.one",
            "dnsseed1.ulord.io",
            "dnsseed1.fcash.cc"
        ]
    ),

    # LBTC mainnet
    Network(
        'LBTC', 'LightningBitcoin', 'mainnet',
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        LBTCTx, BitcoinBlock,
        h2b('F9BEB4D9'), 9333, [
            "seed1.lbtc.io",
            "seed2.lbtc.io",
            "seed3.lbtc.io"
        ]
    ),

    # OMNI bitcoin mainnet : xprv/xpub
    Network(
        'OMNI', "Bitcoin", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        LegacyBitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ],
        bech32_hrp='bc'
    ),

    # MONA Monacoin mainnet : Ltpv/Ltub
    Network(
        "MONA", "Monacoin", "mainnet",
        b'\xb0', b'\x32', b'\37',
        h2b('0488ade4'), h2b('0488b21e'),
        LegacyBitcoinTx, BitcoinBlock,
        h2b('fbc0b6db'), 9401, [
            "dnsseed.monacoin.org",
        ],
        bech32_hrp='mona'
    ),

    # MONA Monacoin testnet : ttpv/ttub
    Network(
        "TMONA", "Monacoin", "testnet4",
        b'\xef', b'\x6f', b'\75',
        h2b('04358394'), h2b('043587cf'),
        LegacyBitcoinTx, BitcoinBlock,
        h2b('fdd2c8f1'), 19403, [
            "testnet-dnsseed.monacoin.org",
        ],
        bech32_hrp='tmona'
    ),
 
]


def _transform_NetworkValues_to_Network(nv):
    defaults = dict(
        tx=None, block=None, magic_header=None, dns_bootstrap=[], default_port=None, bech32_hrp=None)
    defaults.update(nv._asdict())
    return Network(**defaults)


def _import_legacy():
    for n in NETWORKS:
        n1 = _transform_NetworkValues_to_Network(n)
        BUILT_IN_NETWORKS.append(n1)


_import_legacy()
