"""HelloWorld Feed Integration for Cortex XSOAR (aka Demisto)

This feed integration is a good example on you can build a Cortex XSOAR feed
using Python 3. Please follow the documentation links below and make sure that
your feed integration follows the Code Conventions and required parameters, and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Feed Required Parameters: https://xsoar.pan.dev/docs/integrations/feeds#required-parameters
Linting: https://xsoar.pan.dev/docs/integrations/linting


The API
--------------

For this template, the feed used as API is OpenPhish, supplying a feed of URLs.
This API's output is of type freetext, and the suitable handling for this type can be seen in the function
'fetch_indicators'. Other APIs may have different formats, so when using this template for other feed APIs
make sure you handle the output properly according to its format.

"""

from typing import Dict, List, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client class to interact with AutoFocus API
    """

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self._http_request('GET',
                                 url_suffix='',
                                 full_url=self._base_url,
                                 resp_type='text',
                                 )

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split('\n')

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append({
                        'value': indicator,
                        'type': auto_detect_indicator_type(indicator),
                        'FeedURL': self._base_url
                    })

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}')
        return result


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    # INTEGRATION FEED DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    client.build_iterator()
    return 'ok'


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            # The indicator value.
            'value': value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'HelloWorld',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from HelloWorld Feed:', indicators,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    indicators = fetch_indicators(client, tlp_color, feed_tags)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Get the service API url
    base_url = params.get('url')

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'helloworld-get-indicators':
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
