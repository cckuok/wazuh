#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from sqlite3 import connect
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        from wazuh.tests.util import RBAC_bypasser, InitWDBSocketMock

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import tasks


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

def get_fake_mitre_data(sql_file):
    """Create a fake database for Tasks."""
    task_db = connect(':memory:')
    cur = task_db.cursor()
    with open(os.path.join(test_data_path, sql_file)) as f:
        cur.executescript(f.read())

    return task_db


a={
  "data": {
    "affected_items": [{"last_update_time": [1606466953], "module": ["upgrade_module"], "agent_id": [2],
                        "node": ["worker2"], "status": ["Legacy"], "command": ["upgrade"],
                        "create_time": [1606466932], "task_id": 1},
                       {"last_update_time": [1606466983], "module": ["upgrade_module"], "agent_id": [3],
                        "node": ["master-node"], "status": ["Failed"], "command": ["upgrade"],
                        "error_message": ["The version of the WPK does not exist in the repository"],
                        "create_time": [1606466983], "task_id": 2},
                       {"last_update_time": [1606467007], "module": ["upgrade_module"], "agent_id": [1],
                        "node": ["worker2"], "status": ["Legacy"], "command": ["upgrade"],
                        "create_time": [1606466989], "task_id": 3},
                       {"last_update_time": [1606467017], "module": ["upgrade_module"], "agent_id": [2],
                        "node": ["worker2"], "status": ["Legacy"], "command": ["upgrade"],
                        "create_time": [1606466998], "task_id": 4},
                       {"last_update_time": [1606467074], "module": ["upgrade_module"], "agent_id": [2],
                        "node": ["worker2"], "status": ["Failed"], "command": ["upgrade"],
                        "error_message": ["The version of the WPK does not exist in the repository"],
                        "create_time": [1606467074], "task_id": 5},
                       {"last_update_time": [1606467114], "module": ["upgrade_module"], "agent_id": [2],
                        "node": ["worker2"], "status": ["Legacy"], "command": ["upgrade"],
                        "create_time": [1606467097], "task_id": 6}
                       ],
    "total_affected_items": 6,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All specified task's status were returned",
  "error": 0
}


# Tests

@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
# @pytest.mark.parametrize("task_list, agent_id, command, node, module, status, select, search, "
#                          "offset, limit, sort, q, tasks_return_value, affected",
#                          [
#                              ([None, None, None, None, None, None, None, None, None, None, None, None, None, None],
#                               {'data': [{'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1, 'node': 'worker1',
#                                          'module': 'upgrade_module',
#                                          'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:08',
#                                          'update_time': '2020/10/22 12:24:21'},
#                                         {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2, 'node': 'worker2',
#                                          'module': 'upgrade_module',
#                                          'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:12',
#                                          'update_time': '2020/10/22 12:24:27'},
#                                         {'error': 0, 'message': 'Success', 'agent': 3, 'task_id': 3, 'node': 'worker2',
#                                          'module': 'upgrade_module',
#                                          'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:12',
#                                          'update_time': '2020/10/22 12:24:27'}]}, True),
#                              ([4], {'data': [{'error': 8, 'message': 'No task in DB', 'task_id': 4}]}, False)
#                          ])
def test_get_task_status_no_filter(mock_task_db):
    """Check system's tasks

    Parameters
    ----------
    task_list : list
        List of task ids
    """
    result = tasks.get_task_status()
    cur = get_fake_mitre_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks")
    rows = cur.fetchone()

    assert result.total_affected_items == rows[0]
