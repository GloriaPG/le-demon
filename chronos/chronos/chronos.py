import os
import sys
import logging
import trollius as asyncio
from trollius import From
import requests
import time
import json
from sentinellad.common import server_mode

logging.getLogger("requests").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

frequency = 60
hostname = os.uname()[1].split('.')[0]

class Monitor(object):
    
    def __init__(self):
        self.url = "%s%s:%s/query?pretty=true&u=%s&p=%s&db=%s&q=" % (config['INFLUX_PROTOCOL'], config['INFLUX_HOST'], config['INFLUX_PORT'], config['INFLUX_USER'], config['INFLUX_PASSWORD'], config['INFLUX_DB'])
        self.set_stla_api_token_header()
        
    def set_stla_api_token_header(self):
        # Get token for API requests
        data_to_send = {'email':_config['sentinella']['user'], 'password':_config['sentinella']['password']}
        response = requests.post(_config['sentinella']['endpoint'] + '/accounts/auth/token', verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)
        if response.status_code == 200:
            self.stla_api_token_header = {'Authorization': 'JWT ' + response.json()['access_token']}
            
    def is_alerted(self, alert_data):
        
        # Parameters alerta.
        event       = 'BeyondThreshold'
        event       = event + self.get_service_from_metric(alert_data['table_name'])['service']
        event       = event + self.get_service_from_metric(alert_data['table_name'])['event']
        service     = self.get_service_from_metric(alert_data['table_name'])['service']
        cloud_id    = alert_data['cloud_id']
        server_id   = alert_data['server_id']
        account_id  = alert_data['account_id']
        server_name = alert_data['server_name']
        logger.info("SERVER NAME : %s", server_name)        
        # Endpoint to search the same alert in alerta.io
        endpoint    = _config['sentinella']['endpoint'] + '/alert_search/?'

        # Query to ask api alerta.io about this alert.
        query_alert = "event={0}".format(event)
        query_alert = query_alert + "&type=metric"
        query_alert = query_alert + "&service={0}".format(service)
        query_alert = query_alert + "&origin=chronos"
        query_alert = query_alert + "&cloud_id={0}".format(cloud_id)
        query_alert = query_alert + "&server_id={0}".format(server_id)
        query_alert = query_alert + "&account_id={0}".format(account_id)
        query_alert = query_alert + "&severity=critical"
        query_alert = query_alert + "&status=open"

        # Request GET to alert.io
        request_url = endpoint + query_alert
        token       = self.stla_api_token_header
        verify      = bool(_config['sentinella']['verify_ssl'])

        logger.info("THE REQUEST : %s", request_url)        

        # Call to api
        response    = requests.get(request_url,headers=token,verify=verify)
        logger.info("THE REQUEST RESPONSE: %s", response)

        # In case status 401 set auth token
        if response.status_code == 401:
            self.set_stla_api_token_header
            token   = self.stla_api_token_header
            response = requests.get(request_url,headers=token,verify=verify)

        if response.status_code != 200:
            return True

        # If result is major to 0 then they are the same alert up.
        result = response.json()
        
        if result['response'] == True and result['alert_data']['total'] > 0:
            return True
        else:
            return False

    def close_alert(self, alert_data):
        #description = "Current Value %s %s Trigger Value %s" % (str(alert_data['curValue']), self.get_inverted_operation(alert_data['operation']), str(alert_data['triValue']))

        description = alert_data['description']

        event = 'BeyondThreshold' + self.get_service_from_metric(alert_data['table_name'])['service']
        alert_type = 'metric'
        service = '["' + self.get_service_from_metric(alert_data['table_name'])['service'] + '"]'
        origin = 'chronos'
        cloud_id = alert_data['cloud_id']
        server_id = alert_data['server_id']
        account_id = alert_data['account_id']
        severity = 'normal'
        status = 'closed'

        data_to_send = {'value': str(alert_data['curValue']),
                        'description': description,
                        'event': event,
                        'server_name': alert_data['server_name'],
                        'type': alert_type,
                        'service': service,
                        'origin': origin,
                        'cloud_id': str(cloud_id),
                        'server_id': str(server_id),
                        'account_id': str(account_id), 
                        'severity': severity,
                        'status': status
                        }
        ###logger.info(data_to_send)
        response = requests.post(_config['sentinella']['endpoint'] + '/alert_new', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)
        if response.status_code == 401:
            self.set_stla_api_token_header
            response = requests.post(_config['sentinella']['endpoint'] + '/alert_new', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)

        ###logger.info('Chronos: %s %s %s %s %s %s', str(alert_data['account_id']), str(alert_data['server_name']), str(service), str(event), str(alert_data['curValue']), str(alert_data['triValue']))
        #logger.debug(response.json()['response'])

        if response.json()['response'] == True:
            return True
        
    def get_inverted_operation(self, operation):
        inverted_operation = False
        
        if operation == '<':
            inverted_operation = '>'
        elif operation == '>':
            inverted_operation = '<'
        elif operation == '<=':
            inverted_operation = '>='
        elif operation == '>=':
            inverted_operation = '<='
            
        return inverted_operation
    
    def get_service_from_metric(self, metric):

        event = ''
        service = metric        
        metric_list = metric.split('.')

        if metric_list[0] == 'openstack':
            if metric_list[2] == 'services':
                service = metric_list[3]
                event = 'service'
            elif metric_list[1] == 'processes':
                service = metric_list[2]
                event = 'process'

        return {'service': service.capitalize(), 'event': event.capitalize()}
        
    def create_alert(self, alert_data):
        msg = "\"table: " + alert_data['table_name']
        msg += "\n\n%s(CurrentValue) %s %s(triggerValue)" % (str(alert_data['curValue']), alert_data['operation'], str(alert_data['triValue']))
        msg += "\n\nmatch rule: " + alert_data['sql'] + alert_data['operation'] + str(alert_data['curValue']) + "\""
        
        #description = "Current Value %s %s Trigger Value %s" % (str(alert_data['curValue']), alert_data['operation'], str(alert_data['triValue']))

        description = alert_data['description']

        event = 'BeyondThreshold' + self.get_service_from_metric(alert_data['table_name'])['service'] + self.get_service_from_metric(alert_data['table_name'])['event']
        alert_type = 'metric'
        service = '["' + self.get_service_from_metric(alert_data['table_name'])['service'] + '"]'
        origin = 'chronos'
        cloud_id = alert_data['cloud_id']
        server_id = alert_data['server_id']
        account_id = alert_data['account_id']
        severity = 'critical'
        status = 'open'
        timeout = 86400

        data_to_send = {'value': str(alert_data['curValue']),
                        'description': description,
                        'event': event,
                        'server_name': alert_data['server_name'],
                        'type': alert_type,
                        'service': service,
                        'origin': origin,
                        'cloud_id': str(cloud_id),
                        'server_id': str(server_id),
                        'account_id': str(account_id), 
                        'severity': severity,
                        'status': status,
                        'timeout': timeout,
                        'explanation': alert_data['explanation']
                        }

        #Raise alert
        response = requests.post(_config['sentinella']['endpoint'] + '/alert_new', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)
        if response.status_code == 401:
            self.set_stla_api_token_header
            response = requests.post(_config['sentinella']['endpoint'] + '/alert_new', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)
        logger.info('Chronos ALERT: %s %s %s %s %s %s', str(alert_data['account_id']), str(alert_data['server_name']), str(service), str(event), str(alert_data['curValue']), str(alert_data['triValue']))
        logger.debug('Response: %s %s', alert_data['server_name'], response.json())

    def check(self):
        
        response = requests.get(_config['sentinella']['endpoint'] + '/thresholds', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']))

        if response.status_code == 200:
            thresholds = response.json()['response']
            

            # Get servers
            response = requests.get(_config['sentinella']['endpoint'] + '/servers_all', headers=self.stla_api_token_header, verify=bool(_config['sentinella']['verify_ssl']))
            if response.status_code == 200:
                servers = response.json()['response']
                servers_down = servers

            for threshold in thresholds:
                tTable = threshold['component']
                tOperation = threshold['operation']
                tValue = threshold['value']
                tAggregation = threshold['aggregation']
                tInterval = threshold['period']
                tDescription = threshold['description']
                tExplanation = threshold['explanation']

                '''
                if tTable != 'openstack.nova-api.services.nova-scheduler.status':
                    continue
                '''
                
                if tTable == 'check':
                    sql = "SELECT %s(value) FROM \"%s\" WHERE time >= now() - %sm GROUP BY account_id, cloud_id, server_id, server_name FILL(0)" %(tAggregation, tTable, tInterval)
                else:
                    sql = "SELECT %s(value) FROM \"%s\" WHERE time >= now() - %sm GROUP BY account_id, cloud_id, server_id, server_name" %(tAggregation, tTable, tInterval)
                res = requests.get(self.url+sql)
                #logger.debug(self.url+sql)
                
                if(res.status_code == 200):
                    items = res.json()
                    logger.info('Checking %s items', len(items['results']))
                    if items['results']:
                        results  = items['results']
                        for result in results:
                            if 'series' in result:
                                for serie in result['series']:
                                    logger.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        
                                    value = serie['values'][0][1]
                                    server_name = serie['tags']['server_name']
                                    cloud_id = serie['tags']['cloud_id']
                                    server_id = serie['tags']['server_id']
                                    account_id = serie['tags']['account_id']
                                    metric = serie['name']

                                    if metric == 'check':
                                        servers_down = [element for element in servers_down if element.get('name') != server_name and element.get('id') != server_id]

                                    # If server_id check is 0, then look if the same server id is active with other cloud_id
                                    if metric == 'check' and value != 1:
                                        ser = filter(lambda k: k['tags']['server_id'] == server_id and k['values'][0][1] == 1, result['series'])
                                        if len(ser) > 0:
                                            continue

                                    if value is not None:
                                        alert_open = False
                                        
                                        if tOperation == ">":
                                            if float(value) > float(tValue):
                                                alert_open = True
                                        elif  tOperation == "<":
                                            if float(value) < float(tValue):
                                                alert_open = True
                                        elif  tOperation == "=":
                                            if float(value) == float(tValue):
                                                alert_open = True
                                        else:
                                            logger.info("Chronos: unknown operation")
                                        '''
                                        if alert_open is True:
                                            logger.info("Chronos: Raise alert!! - %s %s %s %s server_id:%s %s", str(metric), str(float(value)), str(tOperation), str(float(tValue)), str(server_id), str(alert_open))
                                        else:
                                            logger.debug("Chronos: Nothing to do - %s server_id:%s %s %s %s", str(metric), str(server_id), str(float(value)), str(self.get_inverted_operation(tOperation)), str(float(tValue)))
                                        '''
                                        alert_data = {'table_name': metric,
                                                      'curValue': value,
                                                      'triValue': tValue,
                                                      'server_name': server_name,
                                                      'cloud_id': cloud_id,
                                                      'server_id': server_id,
                                                      'account_id': account_id,
                                                      'sql': sql,
                                                      'operation': tOperation,
                                                      'description': tDescription,
                                                      'explanation': tExplanation}
                                        
                                        is_alerted = self.is_alerted(alert_data)
                       
                                        logger.info("[%s] (%s) %s(%s)(%s)(%s), alert_open: %s, is_alerted: %s, %s %s %s", metric, self.get_service_from_metric(metric)['service'], server_name, account_id, cloud_id, server_id, alert_open, is_alerted, value, tOperation, tValue)
                                        
                                        # Is Server in mode maintenace or blackout ?
                                        maintenance = False
                                        blackout    = False
                                        
                                        if server_id != "" and server_id:
                                            result      = server_mode(server_id,_servers_maintenance,_servers_blackout)
                                            maintenance = result['maintenance'] # Then, not send Alert
                                            blackout    = result['blackout']

                                        if maintenance is False or blackout is False:
                                            if alert_open is True and is_alerted is not True:
                                                logger.info("*** Chronos: Raising Alert for server_id: %s ****", server_id)
                                                self.create_alert(alert_data)
                                            else:
                                                logger.info('Nothing to see here, move along')
                                        else:
                                            logger.info('Nothing to see here, move along, server in maintenance or blackout')
                                        
                                        logger.info("********************************************************")
                                        
                                    else:
                                        logger.info('Chronos: nothing to do, null value %s %s %s %s %s %s %s %s', str(metric), str(account_id), str(server_name), str(cloud_id), str(server_id), str(tAggregation), str(tTable), str(tInterval))
                    else:
                        logger.info("Chronos: No serie")
                else:
                    logger.info("Chronos: Invalid InfluxDB response")

                # Send alerts (check) for non-existant server data on InfluxDB
                if tTable == 'check':
                    for server in servers_down:
                        if server['name'] == 'lab':
                            logger.info("===== SERVERS DOWN =====")
                            value = 0
                            server_name = server['name']
                            cloud_id = server['cloud_id']
                            server_id = server['id']
                            account_id = server['account_id']
                            metric = 'check'

                            if value is not None:
                                alert_open = False

                                if tOperation == ">":
                                    if float(value) > float(tValue):
                                        alert_open = True
                                elif  tOperation == "<":
                                    if float(value) < float(tValue):
                                        alert_open = True
                                elif  tOperation == "=":
                                    if float(value) == float(tValue):
                                        alert_open = True
                                else:
                                    logger.info("Chronos: unknown operation")

                            alert_data = {'table_name': metric,
                                          'curValue': value,
                                          'triValue': tValue,
                                          'server_name': server_name,
                                          'cloud_id': cloud_id,
                                          'server_id': server_id,
                                          'account_id': account_id,
                                          'sql': '',
                                          'operation': tOperation,
                                          'description': tDescription,
                                          'explanation': tExplanation}

                            is_alerted = self.is_alerted(alert_data) 

                            logger.info("[%s] (%s) %s(%s)(%s)(%s), alert_open: %s, is_alerted: %s, %s %s %s", metric, self.get_service_from_metric(metric)['service'], server_name, account_id, cloud_id, server_id, alert_open, is_alerted, value, tOperation, tValue)

                            if alert_open is True and is_alerted is not True:
                                logger.info("*** Chronos: CHECK ALERT Raising Alert for server_id: %s ****", server_id)
                                self.create_alert(alert_data)
                            else:
                                logger.info('Nothing to see here, move along')

@asyncio.coroutine
def check_influxdb_metrics(daemon):
    yield From(daemon.run_event.wait())
    global config
    config = daemon.config['chronos']
    logger.info('starting check_influxdb_metrics')
    global _config
    _config = daemon._config

    # Declare global var with servers in maintenance and blackout
    global _servers_maintenance
    global _servers_blackout

    request_url = _config['sentinella']['endpoint'] + '/servers_all'
    verify = bool(_config['sentinella']['verify_ssl'])
    token = ""
    
    # Get token for API requests
    data_to_send = {'email':_config['sentinella']['user'], 'password':_config['sentinella']['password']}
    response = requests.post(_config['sentinella']['endpoint'] + '/accounts/auth/token', verify=bool(_config['sentinella']['verify_ssl']), json=data_to_send)
    if response.status_code == 200:
        token  = {'Authorization': 'JWT ' + response.json()['access_token']}
    response = requests.get(request_url,headers = token,verify = verify)
    logger.info('Response servers all: %s',str(response))

    if response.status_code == 401:
        self.set_stla_api_token_header
        response = requests.get(request_url,headers = token,verify = verify)

    # Fill global vars with servers in maintenance and blackout
    if response.status_code == 200:
        servers = response.json()['response']
        _servers_maintenance = [element for element in servers if bool(element.get('maintenance')) is True]
        _servers_blackout    = [element for element in servers if bool(element.get('blackout')) is True]

    if response.status_code != 200:
        _servers_maintenance = None
        _servers_blackout = None

    while daemon.run_event.is_set():
        yield From(asyncio.sleep(frequency))
        try:
            Monitor().check()

            #logger.debug('{}: server_usage={}%'.format(hostname, data))
            #yield From(daemon.async_push(data))
            #prev_io_counters = curr_io_counters
        except:
            logger.exception('cannot check influxdb metrics')
    logger.info('get_server_usage terminated')