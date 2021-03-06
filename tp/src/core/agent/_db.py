import logging

from vFense.db.client import db_create_close, r
from vFense.core.agent import *
from vFense.plugins.patching import *
from vFense.core.decorators import return_status_tuple, time_it

logging.config.fileConfig('/opt/TopPatch/conf/logging.config')
logger = logging.getLogger('rvapi')

@time_it
@db_create_close
def fetch_production_levels_from_agent(customer_name, conn=None):
    """
    Retrieve all the production levels that is in the database
    :param customer_name: (Optional) Name of the customer, where the agent
        is located
    Basic Usage::
        >>> from vFense.core.agent._db import fetch_production_levels_from_agent
        >>> customer_name = 'default'
        >>> fetch_production_levels_from_agent(customer_name)
        [
            u'Development',
            u'Production'
        ]
    """
    data = []
    try:
        data = (
            r
            .table(AgentsCollection)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .pluck(AgentKey.ProductionLevel)
            .distinct()
            .map(lambda x: x[AgentKey.ProductionLevel])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_supported_os_strings(customer_name, conn=None):
    """
    Retrieve all the operating systems that is in the database
    :param customer_name: (Optional) Name of the customer, where the agent
        is located
    Basic Usage::
        >>> from vFense.core.agent._db import fetch_supported_os_strings
        >>> customer_name = 'default'
        >>> fetch_supported_os_strings(customer_name)
        [
            u'CentOS 6.5',
            u'Ubuntu 12.04',
            u'Windows 7 Professional Service Pack 1',
            u'Windows 8.1 '
        ]
    """
    data = []
    try:
        data = (
            r
            .table(AgentsCollection)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .pluck(AgentKey.OsString)
            .distinct()
            .map(lambda x: x[AgentKey.OsString])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_agent_ids(customer_name=None, agent_os=None, conn=None):
    """
    :param customer_name: (Optional) Name of the customer, where the agent
        is located
    :param agent_os: (Optional) linux or windows or darwin
    Basic Usage::
        >>> from vFense.core.agent._db import fetch_agent_ids
        >>> customer_name = 'default'
        >>> os_code = 'os_code'
        >>> fetch_agent_ids(customer_name, os_code)
        [
            u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'3ea8fd7a-8aad-40da-aff0-8da6fa5f8766'
        ]
    """
    data = []
    try:
        if customer_name and agent_os:
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({AgentKey.OsCode: agent_os})
                .map(lambda x: x[AgentKey.AgentId])
                .run(conn)
            )

        elif customer_name and not agent_os:
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .map(lambda x: x[AgentKey.AgentId])
                .run(conn)
            )

        elif agent_os and not customer_name:
            data = list(
                r
                .table(AgentsCollection)
                .filter({AgentKey.OsCode: agent_os})
                .map(lambda x: x[AgentKey.AgentId])
                .run(conn)
            )

        elif not agent_os and not customer_name:
            data = list(
                r
                .table(AgentsCollection)
                .map(lambda x: x[AgentKey.AgentId])
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_agents(
    customer_name=None, filter_key=None, filter_val=None,
    keys_to_pluck=None, conn=None):
    """
    :param customer_name: (Optional) Name of the customer, where the agent
        is located
    :param filter_key: (Optional) The name of the key that you are filtering on.
    :param filter_val: (Optional) The value that you are searching for.
    :param keys_to_pluck: (Optional) Specific keys that you are retrieving
        from the database
    Basic Usage::
        >>> from vFense.core.agent._db import fetch_agents
        >>> key = 'os_code'
        >>> val = 'linux'
        >>> pluck = ['computer_name', 'agent_id']
        >>> fetch_agents(customer_name, key, val, pluck)
        [
            {
                u'agent_id': u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
                u'computer_name': u'ubuntu'
            },
            {
                u'agent_id': u'3ea8fd7a-8aad-40da-aff0-8da6fa5f8766',
                u'computer_name': u'localhost.localdomain'
            }
        ]
    """

    data = []
    try:
        if filter_key and filter_val and not customer_name and not keys_to_pluck:
            data = list(
                r
                .table(AgentsCollection)
                .filter({filter_key: filter_val})
                .run(conn)
            )

        elif filter_key and filter_val and customer_name and not keys_to_pluck:
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({filter_key: filter_val})
                .run(conn)
            )

        elif filter_key and filter_val and keys_to_pluck and not customer_name:
            data = list(
                r
                .table(AgentsCollection)
                .filter({filter_key: filter_val})
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif filter_key and filter_val and keys_to_pluck and customer_name:
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({filter_key: filter_val})
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (not filter_key and not filter_val
                and not customer_name and keys_to_pluck):
            data = list(
                r
                .table(AgentsCollection)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (not filter_key and not filter_val
                and customer_name and keys_to_pluck):
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (not filter_key and not filter_val
                and not customer_name and not keys_to_pluck):
            data = list(
                r
                .table(AgentsCollection)
                .run(conn)
            )

        elif (not filter_key and not filter_val
                and customer_name and not keys_to_pluck):
            data = list(
                r
                .table(AgentsCollection)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_agent_info(agent_id, keys_to_pluck=None, conn=None):
    """
    :param agent_id: 36 character uuid of the agent you are updating
    :param keys_to_pluck: (Optional) Specific keys that you are retrieving
        from the database
    Basic Usage::
        >>> from vFense.core.agent._db import fetch_agent_info
        >>> agent_id = '52faa1db-290a-47a7-a4cf-e4ad70e25c38'
        >>> keys_to_pluck = ['production_level', 'needs_reboot']
        >>> fetch_agent_info(agent_id, keys_to_pluck)
        {
            u'agent_id': u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'production_level': u'Development'
        }
    """

    data = []
    try:
        if agent_id and keys_to_pluck:
            data = (
                r
                .table(AgentsCollection)
                .get(agent_id)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif agent_id and not keys_to_pluck:
            data = (
                r
                .table(AgentsCollection)
                .get(agent_id)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def update_agent_data(agent_id, agent_data, conn=None):
    """
    :param agent_id: 36 character uuid of the agent you are updating
    :param agent_data: Dictionary of the data you are updating

    Basic Usage::
        >>> from vFense.core.agent._db import update_agent_data
        >>> agent_id = '0a1f9a3c-9200-42ef-ba63-f4fd17f0644c'
        >>> data = {'production_level': 'Development', 'needs_reboot': 'no'}
        >>> update_agent(agent_id, data)
        >>> (2001, 1)
    """
    data = {}
    try:
        data = (
            r
            .table(AgentsCollection)
            .get(agent_id)
            .update(agent_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def insert_agent_data(agent_data, conn=None):
    """
    :param agent_data: Can either be a list of dictionaries or a dictionary
        of the data you are inserting.

    Basic Usage::
        >>> from vFense.core.agent._db import insert_agent_data
        >>> agent_data = {'customer_name': 'vFense', 'needs_reboot': 'no'}
        >>> insert_agent_data(agent_data)
        >>> (2001, 1, None, [u'317e4228-047f-450a-9f38-a554af098e0a'])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentsCollection)
            .insert(agent_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)
