from __future__ import unicode_literals
from datetime import timedelta
import functools
import glob
import inspect
import json
import logging
import os
import signal
import threading
from string import Template

import trollius as asyncio
from trollius import From
from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
import requests
from requestsexceptions import InsecurePlatformWarning

logger = logging.getLogger(__name__)


def _to_hours(period):
    if period[-1] == 'h':
        return period
    elif period[-1] == 'w':
        td = timedelta(weeks=int(period[:-1]))
        return '%dh0m0s' % int(td.total_seconds() / 3600)
    elif period[-1] == 'd':
        td = timedelta(days=int(period[:-1]))
        return '%dh0m0s' % int(td.total_seconds() / 3600)


class Tourbillon(object):

    """create a tourbillon instance reading its configuration from config_file
    """

    def __init__(self, config_file):
        super(Tourbillon, self).__init__()

        self._aio_run_event = asyncio.Event()
        self._thr_run_event = threading.Event()
        self._loop = asyncio.get_event_loop()
        self._tasks = []
        self._pluginconfig = {}

        with open(config_file, 'r') as f:
            self._config = json.load(f)

        formatter = logging.Formatter(fmt=self._config['log_format'])
        handler = logging.handlers.WatchedFileHandler(
            self._config['log_file'])
        handler.setFormatter(formatter)
        handler.setLevel(getattr(logging, self._config['log_level']))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(
            getattr(logging, self._config['log_level']))

        logger.info('Use config file: %s', config_file)

        self._load_plugins_config(os.path.abspath(
                                  os.path.dirname(config_file)))
        
        print "[Sentinel.la Daemon]"

    def _load_plugins_config(self, tourbillon_conf_dir):
        t = Template(self._config['plugins_conf_dir'])
        plugin_conf_dir = t.safe_substitute(
            tourbillon_conf_dir=tourbillon_conf_dir)
        logger.info('Plugin config dir: %s', plugin_conf_dir)
        config_files = glob.glob(os.path.join(plugin_conf_dir,
                                              '*.conf'))
        for file_name in config_files:
            k = os.path.splitext(os.path.basename(file_name))[0]
            with open(file_name, 'r') as f:
                try:
                    self._pluginconfig[k] = json.load(f)
                except:
                    logger.exception('error loading config file %s', file_name)

    @property
    def config(self):
        """returns a dictionary that contains configuration for each enabled
        plugin"""

        return self._pluginconfig

    @property
    def run_event(self):
        """get the asyncio.Event or threading.Event"""

        cf = inspect.currentframe()
        caller_name = cf.f_back.f_code.co_name
        caller = cf.f_back.f_globals[caller_name]
        if asyncio.iscoroutinefunction(caller) or asyncio.iscoroutine(caller):
            return self._aio_run_event
        else:
            return self._thr_run_event

    def push_log(self, log):
        """write syncronously log to Sentinel.la API"""
        log['account_key'] = self._config['account_key']
        r = requests.post(self.api_url + '/logs', json=log)
        logger.info('{}: - {} - push_log={}%'.format(log['component'], r.status_code, log))
        return

    def push(self, metrics):
        """write syncronously metrics & stats to Sentinel.la API"""
        metrics['account_key'] = self._config['account_key']
        metrics['measurements'] = json.dumps(metrics['measurements'])
        metrics['specs'] = json.dumps(metrics['stats'])
        r = requests.post(self.api_url + '/metrics', json=metrics)
        logger.info('{}: - {} - push={}%'.format(metrics['server_name'], r.status_code, r.text))
        return

    def create_database(self, name, duration=None, replication=None,
                        default=True):
        return

    @asyncio.coroutine
    def async_push(self, points):
        """write asyncronously datapoints to Sentinel.la API"""
        yield From(self._loop.run_in_executor(
            None,
            functools.partial(self.push,
                              points)))

    @asyncio.coroutine
    def async_create_database(self, name, duration=None, replication=None,
                              default=True):
        return

    def _load_tasks(self):
        if 'plugins' not in self._config:
            logger.warn('no plugin configured.')
            return
        plugins = self._config['plugins']
        thread_targets_count = 0
        for module_name, functions in plugins.items():
            logger.debug('search for tasks in module %s', module_name)
            module = import_module(module_name)
            logger.debug('module %s successfully imported', module_name)
            for task_name in functions:
                logger.debug('checking declared task %s', task_name)
                if hasattr(module, task_name):
                    candidate_task = getattr(module, task_name)
                    task_type = ''
                    if asyncio.iscoroutinefunction(candidate_task):
                        self._tasks.append(asyncio.async(
                            candidate_task(self)))
                        task_type = 'coroutine'
                    else:
                        self._tasks.append(self._loop.run_in_executor(
                            None,
                            candidate_task,
                            self))
                        task_type = 'function'
                        thread_targets_count += 1
                    logger.info('task found: %s.%s, type=%s',
                                module_name, task_name, task_type)
        if thread_targets_count > 0:
            self._loop.set_default_executor(ThreadPoolExecutor(
                max_workers=thread_targets_count + 2)
            )
        logger.debug('configured tasks: %s', self._tasks)

    def stop(self):
        """stop the sentinellad daemon"""

        self._loop.remove_signal_handler(signal.SIGINT)
        self._loop.remove_signal_handler(signal.SIGTERM)
        logger.info('shutting down sentinellad...')
        self._aio_run_event.clear()
        self._thr_run_event.clear()

    def run(self):
        """start the sentinellad daemon"""
        logger.info('starting sentinellad...')
        self._loop.add_signal_handler(signal.SIGINT, self.stop)
        self._loop.add_signal_handler(signal.SIGTERM, self.stop)
        self._load_tasks()
        self._aio_run_event.set()
        self._thr_run_event.set()
        logger.info('sentinellad started')
        if len(self._tasks) > 0:
            self._loop.run_until_complete(asyncio.wait(self._tasks))
        else:
            logger.info('sentinellad no tasks assigned')
        logger.info('sentinellad shutdown completed')