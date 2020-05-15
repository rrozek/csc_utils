import json
import sys
import os


def parse_one_file(filepath):
    if not os.path.isabs(filepath):
        print(f'Please provide abs path for a file. Path provided: {filepath}')
        return
    with open(filepath, 'r') as file:
        json_file = json.load(file)
        if 'ledger' not in json_file['result']:
            # print(f'file: {filepath} does not contain ledger data')
            return None
        ledger_index = json_file['result']['ledger']['ledger_index']
        ledger_hash = json_file['result']['ledger']['ledger_hash']
        account_state = json_file['result']['ledger']['accountState']
        # print(f'account_state size: {len(account_state)}')
        total_balance = 0
        for account in account_state:
            if account['LedgerEntryType'] == 'AccountRoot':
                total_balance += int(account['Balance'])
        summary = {
            'ledger_index': ledger_index,
            'ledger_hash': ledger_hash,
            'total_balance': total_balance,
            'account_count': len(account_state)
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
