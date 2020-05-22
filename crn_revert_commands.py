import subprocess
import time
import json
import os

sleepTime = 7
appName = "casinocoind"
confPath = "--conf=/etc/casinocoind/casinocoind.cfg"
method = "submit"

revert_file = "result.json"
with open(revert_file, 'r') as the_file:
    result_json = json.load(the_file)
    todos = result_json['todo']

    execution_result = {'todo': todos, 'result': []}
    for item in todos:
        cscSignCmd = item['command']
        sign_output = subprocess.check_output(cscSignCmd)
        json_sign_output = json.loads(sign_output)

        tx_blob = json_sign_output['result']['tx_blob']
        cscSubmitCmd = [appName, confPath, method, tx_blob]
        submit_output = subprocess.check_output(cscSubmitCmd)
        json_submit_output = json.loads(submit_output)

        result_trace = {
          'sign_cmd': ' '.join(cscSignCmd),
          'sign_output': json_sign_output,
          'submit_cmd': ' '.join(cscSubmitCmd),
          'submit_output': json_submit_output
        }
        execution_result['result'].append(result_trace)
        print(result_trace)
        time.sleep(sleepTime)

    result_filepath = os.path.join(os.curdir, 'execution_result.json')
    with open(result_filepath, 'w') as result_file:
        json.dump(execution_result, result_file)
        print('results stored in')
        print(os.path.abspath(result_filepath))

