import os
import logging
import requests
import tornado.ioloop
import tornado.web
import tornado.gen
import tornado.websocket
import tornado.httpserver
from sentinellad.common import server_mode
from tornado.concurrent import Future

from jinja2 import Environment, FileSystemLoader #For templating stuff

import rethinkdb as r #For db stuff
from rethinkdb.errors import RqlRuntimeError, RqlDriverError

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

stla_api_token_header = ''

def send_rethink_events(daemon):
    logger.info('send_rethink_events started')
    daemon.run_event.wait()
    config = daemon.config['aeolus']
    logger.info('antes_production')
    logger.info(config)
    if config['RDB_ENVIRONMENT'] == 'production':
        logger.info('production')
        try:
            db_connection = r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], auth_key=config['RDB_AUTH_KEY'], ssl={'ca_certs': '/etc/sentinellad/certificates/composecert_new'})
        except:
            logger.info('Error stablishing DB connection')
    else:
        logger.info('development')
        try:
            db_connection = r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], password=config['RDB_PASS'])
        except:
            logger.info('Error stablishing DB connection')
    logger.info('Initiating Tornado') 
    r.set_loop_type("tornado")
    
    class MainHandler(tornado.web.RequestHandler):
        @tornado.gen.coroutine
        def get(self):
            output = 'Nothing to see here, move along, move along.'
            self.write(output)
            
        @tornado.gen.coroutine
        def send_log_alert():
            while True:
                try:
                    #temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], auth_key=config['RDB_AUTH_KEY'])
                    
                    if config['RDB_ENVIRONMENT'] == 'production':
                        try:
                            temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], auth_key=config['RDB_AUTH_KEY'], ssl={'ca_certs': '/etc/sentinellad/certificates/composecert_new'})
                        except:
                            logger.info('Error stablishing DB connection')
                    else:
                        logger.info('development')
                        try:
                            temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], password=config['RDB_PASS'])
                        except:
                            logger.info('Error stablishing DB connection')

                    if temp_conn:
                        print 'Connected to ' + config['RDB_HOST']
        
                    feed = yield r.db(config['RDB_DB']).table(config['RDB_TABLE']).changes().run(temp_conn)
                                       
                    allowed_alert_levels = ['WARNING', 'CRITICAL', 'ERROR']
                    while (yield feed.fetch_next()):
                        new_log_alert = yield feed.next()
                        level = new_log_alert['new_val']['level']
                        server_name = new_log_alert['new_val']['server_name']
        
                        if level.upper() in allowed_alert_levels:
                            data_to_send = {}
                            data_to_send = new_log_alert['new_val']
                            data_to_send['value'] = data_to_send['log_id']
                            data_to_send['event'] = data_to_send['level']
                            data_to_send['service'] = data_to_send['component']
                            req = requests.post(daemon._config['sentinella']['endpoint'] + '/alerts', verify=False, data=data_to_send)
                            logger.info('Rething log: %s %s %s %s', str(req), str(data_to_send['account_key']), str(server_name), str(level))
                            logger.info('Rething log: (data) %s', str(data_to_send))
                except ValueError:
                    print ValueError
                    pass
                
    class WSocketHandler(tornado.websocket.WebSocketHandler): #Tornado Websocket Handler
        def check_origin(self, origin):
            return True
    
        def open(self):
            self.stream.set_nodelay(True)
            
    def set_stla_api_token_header():
        global stla_api_token_header
        # Get token for API requests
        data_to_send = {'email':daemon._config['sentinella']['user'], 'password':daemon._config['sentinella']['password']}
        response = requests.post(daemon._config['sentinella']['endpoint'] + '/accounts/auth/token', verify=bool(daemon._config['sentinella']['verify_ssl']), json=data_to_send)
        
        if response.status_code == 200:
            stla_api_token_header = {'Authorization': 'JWT ' + response.json()['access_token']}
        
    set_stla_api_token_header()
    print stla_api_token_header
        
    def create_alert(alert_data):
        allowed_alert_levels = []        
        description = alert_data['level'] + " event on " + alert_data['service_name'] + " [" + alert_data['component'] + "] : " + alert_data['description']

        alert_type = 'log'
        
        if 'component' in alert_data:
            component = alert_data['component']
        else:
            component = ''
        
        if 'service_name' in alert_data:
            service = '["' + alert_data['service_name'] + '"]'
        else:
            service ='["' + alert_data['service'] + '"]'

        event = alert_data['level'] + ' on ' + component
        
        origin = 'aeolus'
        
        cloud_id = alert_data['cloud_id'] if 'cloud_id' in alert_data else ''
        server_id = alert_data['server_id'] if 'server_id' in alert_data else ''
        account_id = alert_data['account_id'] if 'account_id' in alert_data else ''
        account_key = alert_data['account_key'] if 'account_key' in alert_data else ''
        timeout = 5 * 60 # 5 minutes
        
        severity = 'warning'
        status = 'ack'

        data_to_send = {'value': str(alert_data['value']),
                        'description': description,
                        'event': event,
                        'server_name': alert_data['server_name'],
                        'type': alert_type,
                        'service': service,
                        'origin': origin,
                        'cloud_id': str(cloud_id),
                        'server_id': str(server_id),
                        'account_id': str(account_id),
                        'account_key': str(account_key),
                        'severity': severity,
                        'status': status,
                        'timeout': timeout,
                        'component': component
                        }
        logger.info(data_to_send)
        # Declare global var with servers in maintenance and blackout
        servers_maintenance = None
        servers_blackout = None
        
        # Call to API to Get all servers
        request_url = daemon._config['sentinella']['endpoint'] + '/servers_all'
        token       = stla_api_token_header
        verify      = bool(daemon._config['sentinella']['verify_ssl'])
        response    = requests.get(request_url,headers=token,verify=verify)
        if response.status_code == 401:
            set_stla_api_token_header()
            response    = requests.get(request_url,headers=stla_api_token_header,verify=verify)
        # Fill global vars with servers in maintenance and blackout
        if response.status_code == 200:
            servers = response.json()['response']
            servers_maintenance = [element for element in servers if element.get('maintenance') is True]
            servers_blackout    = [element for element in servers if element.get('blackout') is True]
        if response.status_code != 200:
            servers_maintenance  = None
            servers_blackout     = None
            logger.info('Servers all are not working!')
        # Is Server in mode maintenace or blackout ?
        maintenance = False
        blackout    = False
        
        if server_id != "" and server_id:
            result      = server_mode(server_id,servers_maintenance,servers_blackout)
            maintenance = result['maintenance'] # Then, not send Alert
            blackout    = result['blackout']
        logger.info("GPG : Valida mantenimiento")
       
        # Global vars for request.
        url_api     = daemon._config['sentinella']['endpoint']

        # Call API to GET thresholds.
        endpoint    = '{0}/thresholds'.format(url_api)
        response    = requests.get(endpoint, headers = token, verify = verify)

        if response.status_code == 401:
            set_stla_api_token_header()
            response    = requests.get(endpoint,headers=stla_api_token_header,verify=verify)

            thresholds  = None

        # If status is 200 then fill var thresholds
        if response.status_code == 200:
            thresholds = response.json()['response']
            logger.info('Response thresholds : {0}'.format(thresholds))

        if thresholds:
            for t in thresholds:
                logger.info("GPG component : " + t['component'].upper())
                if t['component'].upper() == "LOGS":
                    logger.info("GPG value : " + t['value'].upper())
                    if t['value'].upper() == "ALL":
                        logger.info( "GPG todos los logs")
                        allowed_alert_levels = ['WARNING', 'CRITICAL', 'ERROR']
                    else:
                        logger.info( "GPG no todos")
                        allowed_alert_levels.append(t['value'].upper())
        logger.info('GPG allowed_alert_levels : {0} '.format(allowed_alert_levels))
        if maintenance is not True or blackout is not True and alert_data['level'].upper() in allowed_alert_levels:

            response = requests.post(daemon._config['sentinella']['endpoint'] + '/alert_new', headers=stla_api_token_header, verify=bool(daemon._config['sentinella']['verify_ssl']), json=data_to_send)
            if response.status_code == 401:
                set_stla_api_token_header()
                response = requests.post(daemon._config['sentinella']['endpoint'] + '/alert_new', headers=stla_api_token_header, verify=bool(daemon._config['sentinella']['verify_ssl']), json=data_to_send)
            logger.info('Create alert: %s %s %s %s', alert_data['account_key'], alert_data['server_name'], str(service), event)
            logger.info('GPG ALERT DATA : ' + str(alert_data))
            logger.info('GPG Response : ' + str(response.json()))
        else:
            logger.info('No Create alert: %s %s %s %s', alert_data['account_key'], alert_data['server_name'], str(service), event)

    @tornado.gen.coroutine
    def send_log_alert():
        while True:
            try:
                #temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], auth_key=config['RDB_AUTH_KEY'])
                
                if config['RDB_ENVIRONMENT'] == 'production':
                    try:
                        temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], auth_key=config['RDB_AUTH_KEY'], ssl={'ca_certs': '/etc/sentinellad/certificates/composecert_new'})
                    except:
                        logger.info('Error stablishing DB connection')
                else:
                    logger.info('development')
                    try:
                        temp_conn = yield r.connect(host=config['RDB_HOST'], port=config['RDB_PORT'], password=config['RDB_PASS'])
                    except:
                        logger.info('Error stablishing DB connection')

                if temp_conn:
                    print 'Connected to ' + config['RDB_HOST']
    
                feed = yield r.db(config['RDB_DB']).table(config['RDB_TABLE']).changes().run(temp_conn)
                allowed_alert_levels = ['ERROR','WARNING','CRITICAL'] 
                while (yield feed.fetch_next()):
                    new_log_alert = yield feed.next()
                    #print new_log_alert
                    level = new_log_alert['new_val']['level']
                    server_name = new_log_alert['new_val']['server_name']
                    logger.debug(level)
                    if level in allowed_alert_levels:
                        data_to_send = {}
                        data_to_send = new_log_alert['new_val']
                        data_to_send['value'] = data_to_send['log_id']
                        data_to_send['event'] = data_to_send['level']
                        logger.info('New event : ' + level)
                        create_alert(data_to_send)
            except ValueError:
                logger.info(ValueError)
                pass
    
    #Define tornado application
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    #static_folder = os.path.join(current_dir, 'static')
    tornado_app = tornado.web.Application([('/', MainHandler)])

    #Start the server
    server = tornado.httpserver.HTTPServer(tornado_app)

    #server.listen(8888) #Bind port 8888 to server
    try:
        tornado.ioloop.IOLoop.current().add_callback(send_log_alert)
    except Exception, e:
        logger.info(e)

    tornado.ioloop.IOLoop.instance().start()
    
    #while daemon.run_event.is_set():
    #tornado.ioloop.IOLoop.instance().stop()

    logger.info('send_rethink_events terminated')
