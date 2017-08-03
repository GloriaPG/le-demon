import os
import sys
import logging
import requests
import time
import json

logger = logging.getLogger(__name__)

def server_mode(server_id,servers_maintenance,servers_blackout):

    result = {'maintenance': False,'blackout':False}

    if servers_maintenance is not None:

        if len(servers_maintenance) > 0:
            server = None
            for it in servers_maintenance:
                if it['id'] == server_id:
                    server = it
            if server is not None:
                logger.info('SERVER : %s  MAINTENANCE : True')
                result['maintenance'] = True

    if servers_blackout is not None:
        if len(servers_blackout) > 0:
            server = None
            for it in servers_blackout:
                if it['id'] == server_id:
                    server = it
            if server:
                logger.info('SERVER : %s  BLACKOUT : True')
                result['blackout'] = True

    return result
