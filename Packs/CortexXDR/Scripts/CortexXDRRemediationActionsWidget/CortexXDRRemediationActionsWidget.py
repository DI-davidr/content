"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerPython import *

import traceback

''' STANDALONE FUNCTION '''

''' COMMAND FUNCTION '''


def indicator_to_clickable(indicator):
    res = demisto.executeCommand('GetIndicatorsByQuery', {'query': f'value:{indicator}'})
    if isError(res[0]):
        return_error('Query for get indicators is invalid')
    res_content = res[0].get('Contents')
    if not res_content:
        return_error(f'Indicator {indicator} was not found')
    indicator_id = res_content[0].get('id')
    incident_url = os.path.join('#', 'indicator', indicator_id)
    return f'[{indicator}]({incident_url})'


def get_remediation_info() -> Dict:
    remediation_actions = demisto.get(demisto.context(), 'RemediationActions')
    blocked_ip_addresses = demisto.get(remediation_actions, 'BlockedIP.Addresses')
    if blocked_ip_addresses is not None and not isinstance(blocked_ip_addresses, list):
        blocked_ip_addresses = [blocked_ip_addresses]
    inactive_access_keys = remediation_actions.get('InactiveAccessKeys')
    if inactive_access_keys is not None and not isinstance(inactive_access_keys, list):
        inactive_access_keys = [inactive_access_keys]
    deleted_login_profiles = demisto.get(remediation_actions, 'DisabledLoginProfile.Username')
    if deleted_login_profiles is not None and not isinstance(deleted_login_profiles, list):
        deleted_login_profiles = [deleted_login_profiles]

    res = {}
    if blocked_ip_addresses:
        res['Blocked IP Addresses'] = [indicator_to_clickable(ip) for ip in blocked_ip_addresses]
    if inactive_access_keys:
        res['Inactive Access keys'] = inactive_access_keys
    if deleted_login_profiles:
        res['Deleted Login Profiles'] = deleted_login_profiles
    return res


''' MAIN FUNCTION '''


def main():
    try:
        result = get_remediation_info()
        command_result = CommandResults(
            readable_output=tableToMarkdown('Remediation Actions Information', result, headers=list(res.keys())))
        return_results(command_result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RemediationActionsWidget. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
