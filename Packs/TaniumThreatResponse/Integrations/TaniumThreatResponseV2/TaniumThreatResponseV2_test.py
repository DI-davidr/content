import io
import json

import pytest

import TaniumThreatResponseV2


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    client = TaniumThreatResponseV2.Client(base_url=BASE_URL, password='TEST', username='TEST')
    return client


BASE_URL = 'https://test.com'
MOCK_CLIENT = mock_client()

''' GENERAL HELPER FUNCTIONS TESTS'''


@pytest.mark.parametrize('test_input, expected_output', [('2', 2), (None, None), (2, 2), ('', None)])
def test_convert_to_int(test_input, expected_output):
    """
    Given -
        An object to convert to int.

    When -
        Running convert_to_int function.

    Then -
        If the object can be converted to int, the function returns the int, otherwise returns None.
    """

    res = TaniumThreatResponseV2.convert_to_int(test_input)
    assert res == expected_output


@pytest.mark.parametrize('test_input, expected_output', [({'testingFunctionFirst': 1, 'testingFunctionSecond': 2},
                                                          {'TestingFunctionFirst': 1, 'TestingFunctionSecond': 2}),

                                                         ([{'testingFunctionFirst': 1}, {'testingFunctionSecond': 2}],
                                                          [{'TestingFunctionFirst': 1}, {'TestingFunctionSecond': 2}])])
def test_format_context_data(test_input, expected_output):
    """
    Given -
        A dict or a list of dicts to format to standard context.

    When -
        Running format_context_data function.

    Then -
        A formatted dict should be returned.
    """

    assert TaniumThreatResponseV2.format_context_data(test_input) == expected_output


''' INTEL DOCS FUNCTIONS TESTS'''


def test_get_intel_doc(requests_mock):
    """
    Given -
        A specific intel doc id.

    When -
        Running get_intel_doc function.

    Then -
        The intel doc details should be returned.
    """

    api_expected_response = util_load_json('test_files/get_intel_doc_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/423', json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_doc(MOCK_CLIENT, {'intel-doc-id': '423'})
    assert '| 423 | get_doc_test |' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'get_doc_test'
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('ID') == 423


def test_get_intel_docs_single(requests_mock):
    """
    Given -
        A specific intel name to obtain.

    When -
        Running get_intel_docs function.

    Then -
        This intel doc details should be returned.
    """

    api_expected_response = util_load_json('test_files/get_intel_docs_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/?name=test2', json=api_expected_response[1])

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs(MOCK_CLIENT, {'name': 'test2'})
    assert '| 430 | test2 |' in human_readable
    intel_docs = outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', [])
    assert intel_docs.get('Name') == 'test2'
    assert intel_docs.get('ID') == 430


def test_get_intel_docs_multiple(requests_mock):
    """
    Given -
        Some data args to filter.

    When -
        Running get_intel_docs function.

    Then -
        A list of all intel docs with their details should be returned.
    """

    api_expected_response = util_load_json('test_files/get_intel_docs_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/', json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs(MOCK_CLIENT, {})
    intel_docs = outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', [])
    assert len(intel_docs) == 3


def test_get_intel_docs_labels_list(requests_mock):
    """
    Given -
        A specific intel-doc ID.

    When -
        Running get_intel_docs_labels_list function.

    Then -
        A list of label IDs of this specific intel-doc.
    """

    intel_doc_id = 423
    api_expected_response = util_load_json('test_files/get_intel_docs_labels_list_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                      json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs_labels_list(MOCK_CLIENT, {
        'intel-doc-id': intel_doc_id})
    assert '| 8 | test3 |' in human_readable
    assert '| 9 | test4 |' in human_readable
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    assert intel_docs.get('IntelDocID') == 423
    labels = intel_docs.get('LabelsList')
    assert len(labels) == 5
    assert labels[1].get('Name') == 'test2'
    assert labels[3].get('ID') == 9


def test_add_intel_docs_label(requests_mock):
    """
    Given -
        A specific intel-doc ID.
        A specific label ID.

    When -
        Running add_intel_docs_label function.

    Then -
        A list of label IDs of this specific intel-doc with the label ID added.
    """

    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_files/add_intel_docs_labels_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    req = requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                            json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.add_intel_docs_label(MOCK_CLIENT,
                                                                                        {'intel-doc-id': intel_doc_id,
                                                                                         'label-id': label_id})
    assert 'Successfully created a new label (3) association for the identified intel document (423).' in human_readable
    assert '| 3 | test6 |' in human_readable
    assert json.loads(req.last_request.text) == {'id': label_id}
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    assert intel_docs.get('IntelDocID') == 423
    labels = intel_docs.get('LabelsList')
    assert len(labels) == 6
    assert labels[1].get('Name') == 'test2'
    assert labels[3].get('ID') == 9


def test_remove_intel_docs_label(requests_mock):
    """
    Given -
        A specific intel-doc ID.
        A specific label ID.

    When -
        Running remove_intel_docs_label function.

    Then -
        A list of label IDs of this specific intel-doc with the label ID removed.
    """

    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_files/get_intel_docs_labels_list_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels/{label_id}',
                         json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.remove_intel_docs_label(MOCK_CLIENT, {
        'intel-doc-id': intel_doc_id,
        'label-id': label_id})
    assert 'Successfully removed the label (3)' in human_readable
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    labels = intel_docs.get('LabelsList')
    for item in labels:
        assert item.get('ID') != 3


def test_create_intel_doc(mocker, requests_mock):
    """
    Given -
        An ioc file content.

    When -
        Running create_intel_doc function.

    Then -
        A new intel-doc should be created with that specific file content.
    """

    with open('test_files/test.ioc') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = '.ioc'
    api_expected_response = util_load_json('test_files/create_intel_docs_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_name_and_content', return_value=("test_name", file_content))
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/detect3/api/v1/intels', json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.create_intel_doc(MOCK_CLIENT, {
        'entry-id': entry_id,
        'file-extension': file_extension})
    assert 'Generic indicator for the virus test.' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'VIRUS TEST'


# def test_update_intel_doc(mocker, requests_mock): TODO waiting for a response from Tanium about that.
#
#     intel_doc_id = 423
#     with open('test_files/test.ioc') as f:
#         file_content = f.read()
#     entry_id = 'Test'
#     file_extension = '.ioc'
#     api_expected_response = util_load_json('test_files/update_intel_docs_raw_response.json')
#     mocker.patch('TaniumThreatResponseV2.get_file_name_and_content', return_value=("test_name", file_content))
#     requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
#     requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{str(intel_doc_id)}',
#                       json=api_expected_response)
#
#     human_readable, outputs, raw_response = TaniumThreatResponseV2.update_intel_doc(MOCK_CLIENT, {
#         'intel-doc-id': intel_doc_id,
#         'entry-id': entry_id,
#         'file-extension': file_extension})
#     assert 'Generic indicator for the virus test updated.' in human_readable
#     assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'VIRUS TEST 2'


def test_deploy_intel(requests_mock):
    """
    Given -
        We want to deploy the intels.

    When -
        Running deploy_intel function.

    Then -
        The deploy process should begin.
    """

    api_raw_response = {
        'data': {
            'taskId': 750
        }
    }
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/intel/deploy',
                       json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.deploy_intel(MOCK_CLIENT, {})
    assert 'Successfully deployed intel.' == human_readable
    assert api_raw_response == raw_response


def test_get_deploy_status(requests_mock):
    """
    Given -
        We want to get the last deploy status.

    When -
        Running get_deploy_status function.

    Then -
        The deploy status details should be returned.
    """

    api_raw_response = {
        'data': {
            'createdAt': '2021-05-02T19:18:00.685Z',
            'modifiedAt': '2021-07-14T10:17:13.050Z',
            'currentRevision': 10,
            'currentSize': 2000,
            'pendingRevision': None,
            'pendingSize': None
        }
    }
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intel/status',
                      json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_deploy_status(MOCK_CLIENT, {})
    assert 'Intel deploy status' in human_readable
    assert outputs.get('Tanium.IntelDeployStatus', {}).get('CurrentRevision') == 10


def test_get_alerts(requests_mock):
    """
    Given -
        We want to get alerts list.

    When -
        Running get_alerts function.

    Then -
        The alerts list should be returned.
    """

    api_raw_response = util_load_json('test_files/get_alerts_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts/',
                      json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_alerts(MOCK_CLIENT, {})
    assert 'Alerts' in human_readable
    assert len(outputs.get('Tanium.Alert(val.ID && val.ID === obj.ID)', [])) == 2


def test_get_alert(requests_mock):
    """
    Given -
        We want to get alerts by id.

    When -
        Running get_alert function.

    Then -
        The alert should be returned.
    """

    api_raw_response = util_load_json('test_files/get_alert_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts/1',
                      json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_alert(MOCK_CLIENT, {'alert-id': 1})
    assert 'Alert information' in human_readable
    assert outputs.get('Tanium.Alert(val.ID && val.ID === obj.ID)', {}).get('ID') == 1


def test_alert_update_state(requests_mock):
    """
    Given -
        We want to update alert status.

    When -
        Running get_alert function.

    Then -
        The alert should be returned.
    """
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.put(BASE_URL + '/plugin/products/detect3/api/v1/alerts/', json={})

    args = {'alert-ids': '1,2',
            'state': 'unresolved'}
    human_readable, outputs, _ = TaniumThreatResponseV2.alert_update_state(MOCK_CLIENT, args)
    assert 'Alert state updated to unresolved' in human_readable
    assert outputs == {}


def test_create_snapshot(requests_mock):
    """
    Given - connection to snapshot.


    When -
        Running create_snapshot function.

    Then -
        The Task_id should be returned.
    """

    api_raw_response = util_load_json('test_files/create_snapshot.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/snapshot',
                       json=api_raw_response)

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.create_snapshot(MOCK_CLIENT, args)
    assert 'Initiated snapshot creation request for' in human_readable
    assert 'Task id: 1' in human_readable
    assert outputs.get('Tanium.SnapshotTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('taskId') == 1
    assert outputs.get('Tanium.SnapshotTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('connection') == 'remote:host:123:'


def test_delete_snapshot(requests_mock):
    """
    Given - snapshot ids to delete

    When -
        Running delete_snapshot function.

    Then -
        The human_readable should be returned.
    """

    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/snapshot',
                         json={})

    args = {'snapshot-ids': '1,2,3'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_snapshot(MOCK_CLIENT, args)
    assert 'deleted successfully.' in human_readable
    assert outputs == {}


def test_list_snapshots(requests_mock):
    """
    Given - list_snapshots command, with limit 2.

    When -
        Running list_snapshots function.

    Then -
        The 2 snapshots should be returned.
    """

    api_raw_response = util_load_json('test_files/list_snapshots.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/snapshot',
                      json=api_raw_response)

    args = {'limit': 2, 'offset': 0}
    human_readable, outputs, _ = TaniumThreatResponseV2.list_snapshots(MOCK_CLIENT, args)
    assert 'Snapshots:' in human_readable
    assert outputs.get('Tanium.Snapshot(val.uuid === obj.uuid)', [{}])[0].get('uuid') == '1234567890'


def test_delete_local_snapshot(requests_mock):
    """
    Given - connection id to delete its local snapshot

    When -
        Running delete_local_snapshot function.

    Then -
        The human_readable should be returned.
    """

    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:',
                         json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_local_snapshot(MOCK_CLIENT, args)
    assert ' was deleted successfully.' in human_readable
    assert outputs == {}


def test_get_connections(requests_mock):
    """
    Given - get_connections command and limit=2.

    When -
        Running get_connections function.

    Then -
        2 connections should be returned.
    """

    api_raw_response = util_load_json('test_files/get_connections.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns',
                      json=api_raw_response)

    args = {'limit': '2', 'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_connections(MOCK_CLIENT, args)
    assert 'Connections' in human_readable
    assert outputs.get('Tanium.Connection(val.id === obj.id)', [{}])[0].get('hostname') == 'hostname'
    assert len(outputs.get('Tanium.Connection(val.id === obj.id)')) == 2


def test_create_connection(requests_mock):
    """
    Given - ip, client_id, hostname to create new connection.

    When -
        Running create_connection function.

    Then -
        The connection_id should be returned.
    """

    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/conns/connect',
                       content=b'remote:hostname:123:')

    args = {'ip': '1.1.1.1',
            'client_id': '123',
            'hostname': 'hostname'}
    human_readable, outputs, _ = TaniumThreatResponseV2.create_connection(MOCK_CLIENT, args)
    assert 'Initiated connection request to ' in human_readable
    assert outputs.get('Tanium.Connection(val.id === obj.id)', {}).get('id') == 'remote:hostname:123:'


def test_delete_connection(requests_mock):
    """
    Given - connection_id to delete

    When -
        Running delete_connection function.

    Then -
        The connection should be deleted without errors.
    """

    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/delete/remote:host:123:', json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_connection(MOCK_CLIENT, args)
    assert 'Connection `remote:host:123:` deleted successfully.' in human_readable
    assert outputs == {}


def test_close_connection(requests_mock):
    """
    Given - connection_id to close

    When -
        Running close_connection function.

    Then -
        The connection should be closed without errors.
    """

    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/close/remote:host:123:', json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.close_connection(MOCK_CLIENT, args)
    assert 'Connection `remote:host:123:` closed successfully.' in human_readable
    assert outputs == {}


def test_get_events_by_connection(requests_mock):
    """
    Given -connection_id and type of events to return in this connection.

    When -
        Running get_events_by_connection function.

    Then -
        The list of events in connection should be returned.
    """

    api_raw_response = util_load_json('test_files/get_events_by_connection.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:hostname:123:/views/process/events',
        json=api_raw_response)

    args = {'limit': '2',
            'offset': '0',
            'connection_id': 'remote:hostname:123:',
            'type': 'process'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_events_by_connection(MOCK_CLIENT, args)
    assert 'Events for remote:hostname:123:' in human_readable
    assert outputs.get('TaniumEvent(val.id === obj.id)', [{}])[0].get('pid') == 1


def test_get_labels(requests_mock):
    """
    Given - limit 2 labels.

    When -
        Running get_labels function.

    Then -
        two labels should be returned.
    """

    api_raw_response = util_load_json('test_files/get_labels.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/labels/',
                      json=api_raw_response)

    args = {'limit': '2', 'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_labels(MOCK_CLIENT, args)
    assert 'Labels' in human_readable
    assert outputs.get('Tanium.Label(val.id === obj.id)', [{}])[0].get('id') == 1
    assert len(outputs.get('Tanium.Label(val.id === obj.id)')) == 2


def test_get_label(requests_mock):
    """
    Given - label id to get.

    When -
        Running get_label function.

    Then -
        The label info should be returned.
    """

    api_raw_response = util_load_json('test_files/get_label.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/labels/1',
                      json=api_raw_response)

    args = {'label-id': 1}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_label(MOCK_CLIENT, args)
    assert 'Label Information' in human_readable
    assert outputs.get('Tanium.Label(val.id && val.id === obj.id)', {}).get('id') == 1


def test_get_events_by_process(requests_mock):
    """
    Given - connection id, process id anf type of events to get.

    When -
        Running get_events_by_process function.

    Then -
        Two pocess events related to connection id and ptid 1 should be returned.
    """

    api_raw_response = util_load_json('test_files/get_events_by_process.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL +
                      '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processevents/1/process?limit=2&offset=0',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'limit': '2',
            'offset': '0',
            'ptid': '1',
            'type': 'Process'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_events_by_process(MOCK_CLIENT, args)
    assert 'Events for process 1' in human_readable
    assert outputs.get('Tanium.ProcessEvent(val.id && val.id === obj.id)', [{}])[0].get('id') == '1'


def test_get_process_info(requests_mock):
    """
    Given - connection id and ptid to get its info.

    When -
        Running get_process_info function.

    Then -
        The process info should be returned.
    """

    api_raw_response = util_load_json('test_files/get_process_info.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/1',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_info(MOCK_CLIENT, args)
    assert 'Process information for process with PTID 1' in human_readable
    assert outputs.get('Tanium.ProcessInfo(val.id === obj.id)', [{}])[0].get('id') == "1"


def test_get_process_children(requests_mock):
    """
    Given - connection id and ptid to get its children.

    When -
        Running get_process_children function.

    Then -
        The process children should be returned.
    """

    api_raw_response = util_load_json('test_files/get_process_children.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/1',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_children(MOCK_CLIENT, args)
    assert 'Children for process with PTID 1' in human_readable
    assert outputs.get('Tanium.ProcessChildren(val.id === obj.id)', [{}])[0].get('id') == "2"


def test_get_parent_process(requests_mock):
    """
    Given - connection id and ptid to get its parent.

    When -
        Running get_parent_process function.

    Then -
        The process parent should be returned.
    """

    api_raw_response = util_load_json('test_files/get_parent_process.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/2',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '2'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_parent_process(MOCK_CLIENT, args)
    assert 'Parent process for process with PTID 2' in human_readable
    assert outputs.get('Tanium.ProcessParent(val.id === obj.id)', [{}])[0].get('id') == "1"


def test_get_process_tree(requests_mock):
    """
    Given - connection id and ptid to get its process tree.

    When -
        Running get_process_tree function.

    Then -
        The process tree should be returned.
    """

    api_raw_response = util_load_json('test_files/get_process_tree.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/2',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '2'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_tree(MOCK_CLIENT, args)
    assert 'Process information for process with PTID 2' in human_readable
    assert outputs.get('Tanium.ProcessTree(val.id && val.id === obj.id)', [{}])[0].get('id') == "1"


# def test_command(requests_mock):
#     """
#     Given -
#
#     When -
#         Running ?????? function.
#
#     Then -
#         The ??? should be returned.
#     """
#
#     api_raw_response = util_load_json('test_files/???????.json')
#     requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
#     requests_mock.???(BASE_URL + '????????',
#                       json=api_raw_response)
#
#     args = {'?????'}
#     human_readable, outputs, _ = TaniumThreatResponseV2.?????(MOCK_CLIENT, args)
#     assert '???????' in human_readable
#     assert outputs.get('Tanium.????()', {}).get('????') == 1
