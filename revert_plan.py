import json
import sys
import os
from binascii import hexlify
import binascii
from hashlib import sha256
import hashlib
from io import BytesIO
import six


def decode_hex(hex_string):
    """Decode a string like "fa4b21" to actual bytes."""
    if six.PY3:
        return bytes.fromhex(hex_string)
    else:
        return hex_string.decode('hex')


def to_bytes(number, length=None, endianess='big'):
    """Will take an integer and serialize it to a string of bytes.

    Python 3 has this, this is originally a backport to Python 2, from:
        http://stackoverflow.com/a/16022710/15677

    We use it for Python 3 as well, because Python 3's builtin version
    needs to be given an explicit length, which means our base decoder
    API would have to ask for an explicit length, which just isn't as nice.

    Alternative implementation here:
       https://github.com/nederhoed/python-bitcoinaddress/blob/c3db56f0a2d4b2a069198e2db22b7f607158518c/bitcoinaddress/__init__.py#L26
    """
    h = '%x' % number
    s = ('0'*(len(h) % 2) + h)
    if length:
        if len(s) > length*2:
            raise ValueError('number of large for {} bytes'.format(length))
        s = s.zfill(length*2)
    s = decode_hex(s)
    return s if endianess == 'big' else s[::-1]


class RippleBaseDecoder(object):
    """Decodes Ripple's base58 alphabet.

    This is what ripple-lib does in ``base.js``.
    """

    alphabet = 'cpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2brdeCg65jkm8oFqi1tuvAxyz'

    @classmethod
    def decode(cls, *a, **kw):
        """Apply base58 decode, verify checksum, return payload.
        """
        decoded = cls.decode_base(*a, **kw)
        assert cls.verify_checksum(decoded)
        payload = decoded[:-4] # remove the checksum
        payload = payload[1:]  # remove first byte, a version number
        return payload

    @classmethod
    def decode_base(cls, encoded, pad_length=None):
        """Decode a base encoded string with the Ripple alphabet."""
        n = 0
        base = len(cls.alphabet)
        for char in encoded:
            n = n * base + cls.alphabet.index(char)
        return to_bytes(n, pad_length, 'big')

    @classmethod
    def verify_checksum(cls, bytes):
        """These ripple byte sequences have a checksum builtin.
        """
        valid = bytes[-4:] == sha256(sha256(bytes[:-4]).digest()).digest()[:4]
        return valid

    @staticmethod
    def as_ints(bytes):
        return list([ord(c) for c in bytes])

    @classmethod
    def encode(cls, data):
        """Apply base58 encode including version, checksum."""
        version = b'\x00'
        bytes = version + data
        bytes += sha256(sha256(bytes).digest()).digest()[:4]   # checksum
        return cls.encode_base(bytes)

    @classmethod
    def encode_base(cls, data):
        # https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py
        # Convert big-endian bytes to integer
        n = int(hexlify(data).decode('utf8'), 16)

        # Divide that integer into base58
        res = []
        while n > 0:
            n, r = divmod(n, len(cls.alphabet))
            res.append(cls.alphabet[r])
        res = ''.join(res[::-1])

        # Encode leading zeros as base58 zeros
        czero = 0 if six.PY3 else b'\x00'
        pad = 0
        for c in data:
            if c == czero:
                pad += 1
            else:
                break
        return cls.alphabet[0] * pad + res


def get_ripple_from_pubkey(pubkey):
    """Given a public key, determine the Ripple address.
    """
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(pubkey).digest())
    return RippleBaseDecoder.encode(ripemd160.digest())


def parse_one_file(filepath):
    if not os.path.isabs(filepath):
        print(f'Please provide abs path for a file. Path provided: {filepath}')
        return
    with open(filepath, 'r') as file:
        json_file = json.load(file)
        if 'CRNs' not in json_file['result']:
            # print(f'file: {filepath} does not contain CRN tx data')
            return None
        ledger_index = json_file['result']['ledger_index']
        tx_hash = json_file['result']['hash']
        claimed_fee_distributed = int(json_file['result']['CRN_FeeDistributed'])
        crns = json_file['result']['CRNs']
        # print(f'crns size: {len(crns)}')
        total_distribution = 0
        for crn in crns:
            total_distribution += int(crn['CRN']['CRN_FeeDistributed'])
        summary = {
            'ledger_index': ledger_index,
            'tx_hash': tx_hash,
            'claimed_fee_distributed': claimed_fee_distributed,
            'actual_fee_distributed': total_distribution,
            'crn_count': len(crns)
        }
        # print(f'{summary}')
        return summary



def parse_dir(the_dir):
    result_list = []
    for filepath in os.listdir(the_dir):
        if filepath.endswith(('.txt', '.log')):
            res = parse_one_file(os.path.join(the_dir, filepath))
            if res:
                result_list.append(res)

    result_list = sorted(result_list, key=lambda x: x['ledger_index'])
    return result_list


''' 
revert plan: pick all distributed amount in CRN tx:
2AEB85090BB24E75626049EA1967F00B3EB5BB79C2BA7FFA1EF7736A22EEA6B3
22672AF79542518FEA90281A0DFD9215AC061EFC565293B980D59185A47224FD
19A9CDCD4640D67C7A3E420D0318DF10A9F9E7CFE7998B5B9514813E45A335B0
921B11566B755273A2343E0F8E3EFDC41517E7B0960B2E81882AAEAEF03868E6
group by crn account id, burn total amount per account minus 25000000 (for the tx fee)
'''
def main():
    the_path = os.path.curdir
    if len(sys.argv) > 1:
        if os.path.exists(sys.argv[1]):
            the_path = os.path.abspath(sys.argv[1])

    if not os.path.isdir(the_path):
        print(f'please provide path to directory containing required full ledger dumps and crn tx info')
        return

    list_of_tx_to_revert = [
        '2AEB85090BB24E75626049EA1967F00B3EB5BB79C2BA7FFA1EF7736A22EEA6B3',
        '22672AF79542518FEA90281A0DFD9215AC061EFC565293B980D59185A47224FD',
        '19A9CDCD4640D67C7A3E420D0318DF10A9F9E7CFE7998B5B9514813E45A335B0',
        '921B11566B755273A2343E0F8E3EFDC41517E7B0960B2E81882AAEAEF03868E6'
    ]
    json_combined = {'tx': [], 'ledger': [], 'todo': []}
    affected_crn_account_ids = []
    for filepath in os.listdir(the_path):
        filepath = os.path.join(the_path, filepath)
        if filepath.endswith(('.txt', '.log')):
            with open(filepath, 'r', encoding='utf-8') as file:
                json_file = json.load(file)
                if 'TransactionType' in json_file['result']:
                    if json_file['result']['TransactionType'] == 'SetCRNRound':
                        if json_file['result']['hash'] not in list_of_tx_to_revert:
                            continue
                        credited_nodes = {}
                        crns = json_file['result']['CRNs']
                        affected_nodes = json_file['result']['meta']['AffectedNodes']
                        # at first verify that CRN[CRN_FeeDistributed]==
                        # (meta[AffectedNodes][ModifiedNode][FinalFields][Balance] - meta[AffectedNodes][ModifiedNode][PreviousFields][Balance])
                        for crn in crns:
                            account_id = get_ripple_from_pubkey(bytearray.fromhex(crn['CRN']['CRN_PublicKey']))
                            if account_id not in credited_nodes:
                                credited_nodes[account_id] = {'Account': account_id}
                            credited_nodes[account_id]['claimed_fee_distributed'] = int(crn['CRN']['CRN_FeeDistributed'])
                        for node in affected_nodes:
                            if node['ModifiedNode']['LedgerEntryType'] == 'AccountRoot':
                                modified_account_id = node['ModifiedNode']['FinalFields']['Account']
                                if modified_account_id not in credited_nodes:
                                    print(f'WARNING. account {modified_account_id} was not mentioned in CRNs array')
                                    continue
                                credited_nodes[modified_account_id]['BalanceBefore'] = int(node['ModifiedNode']['PreviousFields']['Balance'])
                                credited_nodes[modified_account_id]['BalanceAfter'] = int(node['ModifiedNode']['FinalFields']['Balance'])
                                credited_nodes[modified_account_id]['meta_fee_distributed'] = int(node['ModifiedNode']['FinalFields']['Balance']) - int(node['ModifiedNode']['PreviousFields']['Balance'])
                                if credited_nodes[modified_account_id]['meta_fee_distributed'] != credited_nodes[modified_account_id]['claimed_fee_distributed']:
                                    print(f"WARNING: account {modified_account_id} has different meta data {credited_nodes[modified_account_id]['meta_fee_distributed']} then CRN_FeeDistributed field {credited_nodes[modified_account_id]['claimed_fee_distributed']}")
                                    credited_nodes[modified_account_id]['status'] = 'invalid'
                                else:
                                    credited_nodes[modified_account_id]['status'] = 'ok'
                                    affected_crn_account_ids.append(modified_account_id)
                                credited_nodes[modified_account_id]['reverts'] = json_file['result']['hash']
                                credited_nodes[modified_account_id]['ledger_index'] = int(json_file['result']['ledger_index'])
                        content = {
                            'hash': json_file['result']['hash'],
                            'ledger_index': int(json_file['result']['ledger_index']),
                            'credited_nodes': credited_nodes
                        }

                        json_combined['tx'].append(content)
    for filepath in os.listdir(the_path):
        filepath = os.path.join(the_path, filepath)
        if filepath.endswith(('.txt', '.log')):
            with open(filepath, 'r', encoding='utf-8') as file:
                json_file = json.load(file)
                if 'ledger' in json_file['result']:
                    ledger_index = int(json_file['result']['ledger']['ledger_index'])
                    ledger_hash = json_file['result']['ledger']['ledger_hash']
                    account_state = json_file['result']['ledger']['accountState']
                    short_account_state = []
                    for account in account_state:
                        if account['LedgerEntryType'] == 'AccountRoot':
                            if account['Account'] in affected_crn_account_ids:
                                acc = {'Account': account['Account'], 'Balance': int(account['Balance'])}
                                short_account_state.append(acc)
                    content = {
                        'ledger_index': ledger_index,
                        'ledger_hash': ledger_hash,
                        'affected_crn_accounts': short_account_state,
                        'affected_crn_account_count': len(short_account_state)
                    }
                    json_combined['ledger'].append(content)
    # at this point we have an array of accounts with the amounts which need to be burned with information which tx they cleanup.
    # we also have list of crn account ids affected and their state in ledger before/after the issue
    # now its time to check if claimed amounts will be inline with ledger data just before the faulty CRNRound and right after CRNRound
    # pick CRNRound ledger index, get ledger before and after, substract amounts and compare with claim of Fee distribution
    for tx in json_combined['tx']:
        issue_ledger_index = tx['ledger_index']
        issue_ledger = {}
        before_ledger = {}
        for ledger in json_combined['ledger']:
            if ledger['ledger_index'] == issue_ledger_index:
                issue_ledger = ledger
            if ledger['ledger_index'] == issue_ledger_index - 1:
                before_ledger = ledger
        for acc in issue_ledger['affected_crn_accounts']:
            if acc['Account'] not in tx['credited_nodes']:
                continue
            tx_acc = tx['credited_nodes'][acc['Account']]
            before_ledger_acc = next(filter(lambda x: x['Account'] == acc['Account'], before_ledger['affected_crn_accounts']))
            if tx_acc['status'] != 'ok':
                print(f"ERROR crn account {tx_acc['Account']} status NOK. requires manual evaluation")
                raise AssertionError
            if acc['Balance'] != tx_acc['BalanceAfter'] or before_ledger_acc['Balance'] != tx_acc['BalanceBefore']:
                print(f"ERROR crn account {tx_acc['Account']} balance check NOK. requires manual evaluation")
                print(acc['Balance'])
                print(tx_acc['BalanceAfter'])
                print(before_ledger_acc['Balance'])
                print(tx_acc['BalanceBefore'])
                raise AssertionError
            json_combined['todo'].append({
                'Account': tx_acc['Account'],
                'RevertAmount': tx_acc['meta_fee_distributed'] - 25000000,
                'RelatedTx': tx['hash'],
                'RelatedLedgerIndex': tx['ledger_index']
            })
    print(f'{json_combined}')
    return


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
