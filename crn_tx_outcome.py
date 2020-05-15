import json
import sys
import os


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


def main():
    """ Main entry point of the app """
    the_path = os.path.curdir
    if len(sys.argv) > 1:
        if os.path.exists(sys.argv[1]):
            the_path = os.path.abspath(sys.argv[1])

    result_list = []
    if os.path.isdir(the_path):
        result_list.append(parse_dir(the_path))
    elif os.path.isfile(the_path):
        result_list.append(parse_one_file(the_path))
    print(f'{result_list}')

    return


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
