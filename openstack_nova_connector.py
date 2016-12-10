#
"""
     module: cisco_csr_connector.py
     short_description: This Phantom app connects to the Cisco CSR platform
     author: Todd Ruch, World Wide Technology
     Revision history:
     25 Aug 2016  |  0.1 - stole base phantom code from Joel King
     21 April 2016  |  1.0 - initial release

     Copyright (c) 2016 World Wide Technology, Inc.

     This program is free software: you can redistribute it and/or modify
     it under the terms of the GNU Affero General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU Affero General Public License for more details.




"""
#
# Phantom App imports
#
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
#
#  system imports
#
import simplejson as json
import time
import requests
import httplib
import logging

REST_PORT = '55443'
TOKEN_RESOURCE = '/auth/token-services'
ACCEPT_HEADERS = {'Accept':'application/json'}


# ========================================================
# AppConnector
# ========================================================


class CSR_Connector(BaseConnector):

    BANNER = "Cisco_CSR"

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(CSR_Connector, self).__init__()

        # standard port for IOS XE REST API
        self.port = REST_PORT
        # base URI with version number
        self.BASE_URI = '/api/v1'
        # resourse URI
        self.PATH_STATIC_ROUTES = '/routing-svc/static-routes'
        # resource for auth token
        self.user = ''
        self.password = ''
        self.device = ''
        self.next_hop_IP = ''
        self.version = 'v1'
        self.destination_network = ''
        self.js = ''
        self.TOKEN_RESOURCE =  TOKEN_RESOURCE
        self.headers = ACCEPT_HEADERS
        self.HEADER = {"Content-Type": "application/json"}
        self.status_code = []
        #logging.basicConfig(filename='/var/log/phantom/cisco_csr_app.log',level=logging.DEBUG)

    def initialize(self):
        """
        This is an optional function that can be implemented by the AppConnector derived class. Since the configuration
        dictionary is already validated by the time this function is called, it's a good place to do any extra initialization
        of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or phantom.APP_ERROR.
        If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get called.
        """
        self.debug_print("%s INITIALIZE %s" % (CSR_Connector.BANNER, time.asctime()))
        self.debug_print("INITAL CONFIG: %s" % self.get_config())
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        This function gets called once all the param dictionary elements are looped over and no more handle_action calls
        are left to be made. It gives the AppConnector a chance to loop through all the results that were accumulated by
        multiple handle_action function calls and create any summary if required. Another usage is cleanup, disconnect
        from remote devices etc.
        """
        self.debug_print("%s FINALIZE Status: %s" % (CSR_Connector.BANNER, self.get_status()))
        return

    def handle_exception(self, exception_object):
        """
        All the code within BaseConnector::_handle_action is within a 'try: except:' clause. Thus if an exception occurs
        during the execution of this code it is caught at a single place. The resulting exception object is passed to the
        AppConnector::handle_exception() to do any cleanup of it's own if required. This exception is then added to the
        connector run result and passed back to spawn, which gets displayed in the Phantom UI.
        """
        self.debug_print("%s HANDLE_EXCEPTION %s" % (CSR_Connector.BANNER, exception_object))
        return


    def _test_connectivity(self, param):
        """
        Called when the user depresses the test connectivity button on the Phantom UI.

            curl -k -X POST https://{device}:55443/api/v1/auth/token-services
                 -H "Accept:application/json" -u "{user}:{pass}" -d ""
        
        """
        action_result = ActionResult(dict(param))          # Add an action result to the App Run
        self.add_action_result(action_result)

        self.debug_print("%s TEST_CONNECTIVITY %s" % (CSR_Connector.BANNER, param))
        config = self.get_config()

        try:
            self.user = config["user"]
            self.password = config["password"]
            self.device = config["trigger_host"]
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
            return self.set_status_save_progress(phantom.APP_ERROR, "KeyError attempting to parse organization ID and name")

        self.debug_print("User: {0}, Password: {1}".format(self.user, self.password))

        self.get_token()
        if self.token:
            #action_result.set_status(phantom.APP_SUCCESS)
            self.debug_print("RECEIVED TOKEN: {0}".format(self.token))
            return self.set_status_save_progress(phantom.APP_SUCCESS, "SUCCESS! Received token from device")
        else:
            #action_result.set_status(phantom.APP_ERROR)
            self.debug_print("DIDN'T RECEIVE TOKEN: BAD THINGS HAPPENED")
            return self.set_status_save_progress(phantom.APP_ERROR, "FAILURE! Unable to obtain token from device")


    def listStaticBlackHoledIPs(self, param):
        """
            curl -k -X GET https://{trigger_rtr}:55443/api/v1/routing-svc/static-routes
                 -H "Accept:application/json" -u "{user}:{pass}"
                 -d ''
        """
        action_result = ActionResult(dict(param))          # Add an action result to the App Run
        self.add_action_result(action_result)

        config = self.get_config()
        self.debug_print(config)

        try:
            self.user = config["user"]
            self.password = config["password"]
            self.device = config["trigger_host"]
            self.next_hop_IP = config['route_to_null']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        self.debug_print("User: {0}, Password: {1}".format(self.user, self.password))
        result = self.get_token()

        # Get the current list of static routes from the Target Host
        api_response = self.api_run('get',self.PATH_STATIC_ROUTES)
        self.debug_print("listStaticBlackHoledIP's result RAW: {0}".format(api_response))
        try:
            route_list = api_response['items']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        #action_result.add_data(route_list)
        # Even if the query was successfull the data might not be available
        if not route_list:
            return action_result.set_status(phantom.APP_ERROR, CISCO_CSR_ERR_QUERY_RETURNED_NO_DATA)
        if route_list:
            routes = []
            for dest in route_list:
                if dest["next-hop-router"] == self.next_hop_IP:
                    action_result.add_data({'destination-network': dest['destination-network']})
                    routes.append(dest['destination-network'])
            #summary = {'routes':routes}
            summary = {'message': "Query returned {0} routes".format(len(route_list))}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
            self.set_status_save_progress(phantom.APP_SUCCESS, "Query returned {0} \
                routes".format(action_result.get_data_size))
        else:
            action_result.set_status(phantom.APP_SUCCESS, CISCO_CSR_SUCC_QUERY)

        return action_result.get_status()


    def setStaticBlackHole(self, param):
        """
        curl -k -X POST -H "Accept:application/json" -H "Content-type:application/json" \
            -H "X-auth-token:{token}" -u "{user}:{pass}" \
            -d '{"destination-network":"7.7.7.10/32","next-hop-router":"192.0.2.1"}' \
            https://10.0.1.10:55443/api/v1/routing-svc/static-routes
        """
        action_result = ActionResult(dict(param))          # Add an action result to the App Run
        self.add_action_result(action_result)
        
        self.debug_print(param)

        config = self.get_config()
        try:
            self.user = config["user"]
            self.password = config["password"]
            self.device = config['trigger_host']
            self.next_hop_IP = config['route_to_null']
            self.destination_network = param['destination-network']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        self.debug_print("Dest_Net: {0}, Device: {1}".format(self.destination_network, self.device))

        self.debug_print("Validate_IP function returns: {0}".format(self.validate_ip()))
        if not self.validate_ip():
            return action_result.set_status(phantom.APP_ERROR, "IP not valid: {0}".format(param["destination-network"]))

        self.js = {"destination-network":self.destination_network, "next-hop-router":self.next_hop_IP}
        result = self.get_token()
        self.debug_print("self.js: {0}".format(self.js))
        # Go get er!
        api_response = self.api_run('post',self.PATH_STATIC_ROUTES)
        self.debug_print("API RESPONSE: {0}".format(api_response))

        if api_response:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully added {0}".format( self.destination_network ))
        else:
            #TODO: Figure out how to send a good error if the route already exists (404 error)
            return action_result.set_status(phantom.APP_ERROR)
        #return action_result.get_status()


    def delStaticBlackHole(self, param):
        """
            curl -k -X DELETE -H "Accept:application/json" -u "{user}:{pass}" -d '' \
                 https://{trigger_rtr}:55443/api/v1/routing-svc/static-routes/{src_IP}_32_192.0.2.1
        """
        action_result = ActionResult(dict(param))          # Add an action result to the App Run
        self.add_action_result(action_result)

        config = self.get_config()
        self.debug_print(param)

        try:
            self.user = config["user"]
            self.password = config["password"]
            self.device = config["trigger_host"]
            self.next_hop_IP = config['route_to_null']
            self.destination_network = param["destination-network"]
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        self.debug_print("User: {0}, Password: {1}".format(self.user, self.password))
        self.debug_print("Dest_Net: {0}, Device: {1}".format(self.destination_network, self.device))

        self.debug_print("Validate_IP function returns: {0}".format(self.validate_ip()))
        if not self.validate_ip():
            return action_result.set_status(phantom.APP_ERROR, "IP not valid: {0}".format(param["destination-network"]))
        dest_net = self.destination_network.split('/')

        result = self.get_token()
        PATH_STATIC_ROUTES = self.PATH_STATIC_ROUTES + "/" + \
                dest_net[0] + "_" + dest_net[1] + "_" + self.next_hop_IP
        api_response = self.api_run('delete',PATH_STATIC_ROUTES)
        self.debug_print("API RESPONSE: {0}".format(api_response))

        if api_response:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted {0}".format( self.destination_network ))
        else:
            #TODO: Figure out how to send a good error if the route already exists (404 error)
            return action_result.set_status(phantom.APP_ERROR)
        #return action_result.get_status()


    def get_token(self):
        """
        Get an auth token from the device
            curl -k -X POST https://{trigger_rtr}:55443/api/v1/auth/token-services/
                 -H "Accept:application/json" -u "{user}:{pass}"
                 -d ''
        """
        result = self.api_run('post',TOKEN_RESOURCE)
        self.debug_print("{0}".format(result))
        self.token = result['token-id']
        self.debug_print("token id: {0}".format(self.token))
        self.headers.update({'X-auth-token':self.token})
        return


    def build_url(self, rest_port=REST_PORT,resource=TOKEN_RESOURCE):
        """ 
        build a URL for the REST resource
        """
        self.url = 'https://{0}:{1}/api/{2}{3}'.format(self.device,self.port,self.version,resource)
        self.debug_print('set full URL to: {0}'.format(self.url))
        return


    def validate_ip(self):
        # Determine if mask is included in IP
        ip_and_mask = self.destination_network.split('/')
        if len(ip_and_mask) != 2:
            self.debug_print("Network Mask not included in {0}".format(self.destination_network))
            # Normalize the IP
            self.destination_network = str(self.destination_network) + '/32'
        ip = ip_and_mask[0].split('.')
        if len(ip) != 4:
            return False
        for x in ip:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True


    def api_run(self, method, resource):
        """
        get/put/post/delete a request to the REST service
        This module requires that the 
        """
        # a GET/POST/PUT/DELETE method name was passed in;
        # call the appropriate method from requests module
        request_method = getattr(requests,method)
        self.debug_print("api_run: {0}".format(request_method))
        self.build_url(resource=resource)
        if self.js:
            self.headers.update({'Content-type':'application/json'})
            result = request_method(self.url, auth=(self.user,self.password),\
                    headers = self.headers,\
                    data = json.dumps(self.js),\
                    verify = False)
        else:
            result = request_method(self.url, auth=(self.user, self.password),\
                    headers = self.headers,\
                    verify = False)
        if result.status_code in [requests.codes.ok]:
            return result.json()
        elif result.status_code in [requests.codes.created, requests.codes.no_content]:
            return True
        #else:
        #    self.interpret_response(r.status_code)


    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector. It gets called for every param dictionary element
        in the parameters array. In it's simplest form it gets the current action identifier and then calls a member function
        of it's own to handle the action. This function is expected to create the results of the action run that get added
        to the connector run. The return value of this function is mostly ignored by the BaseConnector. Instead it will
        just loop over the next param element in the parameters array and call handle_action again.

        We create a case structure in Python to allow for any number of actions to be easily added.
        """

        action_id = self.get_action_identifier()           # action_id determines what function to execute
        self.debug_print("%s HANDLE_ACTION action_id:%s parameters:\n%s" % (CSR_Connector.BANNER, action_id, param))

        supported_actions = {"test connectivity": self._test_connectivity,
                             "list_networks": self.listStaticBlackHoledIPs,
                             "block_network": self.setStaticBlackHole,
                             "unblock_network": self.delStaticBlackHole
                             }

        run_action = supported_actions[action_id]

        return run_action(param)


# =============================================================================================
# Logic for testing interactively e.g. python2.7 ./cisco_csr_connector.py ./test_jsons/test.json
# If you don't reference your module with a "./" you will encounter a 'failed to load app json'
# =============================================================================================

if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:                           # input a json file that contains data like the configuration and action parameters,
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))

        connector = CSR_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ("%s %s" % (connector.BANNER, json.dumps(json.loads(ret_val), indent=4)))

    exit(0)
