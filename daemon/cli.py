#!/usr/bin/env python
from importlib import import_module
import json
import sys
import os
import pip
try:
    from urllib.request import urlopen
except ImportError:
    from urllib import urlopen

import click

PY34_PLUS = sys.version_info[0] == 3 and sys.version_info[1] >= 4
PY27 = sys.version_info[0] == 2 and sys.version_info[1] == 7

LOG_FORMAT_EX = '%(asctime)s %(levelname)s [%(name)s %(filename)s:'\
    '%(funcName)s:%(lineno)d] %(message)s'
LOG_FORMAT_NO = '%(asctime)s %(levelname)s %(message)s'
LOG_FILENAME = '/var/log/sentinellad/sentinellad.log'

INDEX_FILE_URL = 'https://raw.githubusercontent.com/Sentinel-la/'\
    'sentinella-daemon/master/plugin_index.json'

def get_index():
    data = urlopen(INDEX_FILE_URL).read()
    if PY34_PLUS:
        data = data.decode()

    index = {k: v for (k, v) in json.loads(data).items()
             if PY34_PLUS and v['py3'] or PY27 and v['py2']}
    return index


@click.group()
@click.version_option(version='0.9.8')
@click.option('--config',
              '-c',
              type=click.Path(exists=False,
                              file_okay=True,
                              dir_okay=False,
                              writable=False,
                              resolve_path=True),
              default='/etc/sentinellad/sentinellad.conf',
              help='specify a different config file',
              metavar='<config_file>')
@click.option('--pidfile',
              '-p',
              type=click.Path(exists=False,
                              file_okay=True,
                              dir_okay=False,
                              writable=False,
                              resolve_path=True),
              default='/var/run/sentinellad/sentinellad.pid',
              help='specify a different pidfile file',
              metavar='<pidfile_file>')
def cli(config, pidfile):
    """sentinellad: send OpenStack logs and metrics to Sentinel.la"""
    pass

@cli.command()
@click.pass_context
@click.option('--compact', default=False, is_flag=True)
def list(ctx, compact):
    """list available sentinellad plugins"""
    index = get_index()

    top = '+{:<20}+{:<5}+{:<60}+{:<35}+-+'.format('-' * 20,
                                                  '-' * 5,
                                                  '-' * 60,
                                                  '-' * 35)
    header = '|{:<20}|{:<5}|{:<60}|{:<35}|F|'.format('name',
                                                     'ver.',
                                                     'description',
                                                     'author')
    line = '|{:<20}|{:<5}|{:<60}|{:<35}|{}|'

    if not compact:
        print(top)
        print(header)
        print(top)

    for name, meta in index.items():
        if not compact:
            print(line.format(name, meta['version'], meta['description'],
                              meta['author'], '*' if meta['featured'] else ''))
        else:
            print(name)
    if not compact:
        print(top)


@cli.command()
@click.pass_context
@click.argument('plugin', nargs=1, required=True)
def install(ctx, plugin):
    """install sentinellad plugin"""
    index = get_index()
    if plugin not in index:
        click.echo(click.style(
                   'plugin {} not found!'.format(plugin), fg='red'))
        return
    pip_args = ['install']
    meta = index[plugin]
    if 'pip_cmd' in meta:
        plugin = meta['pip_cmd']
    else:
        plugin = '{}=={}'.format(plugin, meta['version'])
    pip_args.append(plugin)
    pip.main(pip_args)


@cli.command()
@click.pass_context
@click.argument('plugin', nargs=1, required=True)
def upgrade(ctx, plugin):
    """upgrade sentinellad plugin"""
    index = get_index()
    if plugin not in index:
        click.echo(click.style(
                   'plugin {} not found!'.format(plugin), fg='red'))
        return
    pip_args = ['install']
    meta = index[plugin]
    if 'pip_cmd' in meta:
        plugin = meta['pip_cmd']
    else:
        plugin = '{}=={}'.format(plugin, meta['version'])
    pip_args = ['install', '-U']
    pip_args.append(plugin)
    pip.main(pip_args)


@cli.command()
@click.pass_context
@click.argument('plugin', nargs=1, required=True)
def reinstall(ctx, plugin):
    """reinstall sentinellad plugin"""
    index = get_index()
    if plugin not in index:
        click.echo(click.style(
                   'plugin {} not found!'.format(plugin), fg='red'))
        return
    pip_args = ['install']
    meta = index[plugin]
    if 'pip_cmd' in meta:
        plugin = meta['pip_cmd']
    else:
        plugin = '{}=={}'.format(plugin, meta['version'])
    pip_args = ['install', '--force-reinstall', '-U']
    pip_args.append(plugin)
    pip.main(pip_args)


@cli.command()
@click.pass_context
def show(ctx):
    """show the list of enabled plugins"""
    config_file = ctx.parent.params['config']
    with open(config_file, 'r') as f:
        config = json.load(f)

    if 'plugins' not in config:
        click.echo('no enabled plugins')
        return

    for key, value in config['plugins'].items():
        click.echo('module: {0} - functions: {1}'.format(
                   key, ', '.join(value)))

def validate_plugins(ctx, param, value):
    result = {}
    for v in value:
        if '=' not in v:
            raise click.BadParameter('plugin %s in not valid' % v)
        module, functions = v.replace(' ', '').split('=')
        result[module] = functions.split(',')
    return result


@cli.command(short_help='enable one or more plugins')
@click.pass_context
@click.argument('plugins', nargs=-1, required=True,
                callback=validate_plugins)
def enable(ctx, plugins):
    """Enable one or more plugins

PLUGINS are expressed in the form:

    module1.submodule1=function1,function2,... module2=function3,...

Example:

    sentinellad enable sentinellad.metrics=get_server_usage

Enable the function get_server_usage of the
'sentinellad.metrics' plugin.
    """
    config_file = ctx.parent.params['config']
    with open(config_file, 'r') as f:
        config = json.load(f)
    if 'plugins' not in config:
        config['plugins'] = {}

    for module, functions in plugins.items():
        try:
            m = import_module(module)
        except:
            click.echo('module %s does not exists' % module)
            continue
        if module not in config['plugins']:
            config['plugins'][module] = []
        for f in functions:
            if not hasattr(m, f):
                click.echo('module %s does not contains %s' % (module, f))
                continue
            if f not in config['plugins'][module]:
                config['plugins'][module].append(f)

        if len(config['plugins'][module]) == 0:
            del config['plugins'][module]

    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2, sort_keys=True)


@cli.command(short_help='disable one or more plugins')
@click.pass_context
@click.argument('plugins', nargs=-1, required=True, callback=validate_plugins)
def disable(ctx, plugins):
    """Disable one or more plugins

PLUGINS are expressed in the form:

    module1.submodule1=function1,function2,... module2=function3,...

Example:

    sentinellad disable sentinellad.metrics=get_server_usage

Disable the function get_server_usage of the
'sentinellad.metrics' plugin
    """
    config_file = ctx.parent.params['config']
    with open(config_file, 'r') as f:
        config = json.load(f)
    if 'plugins' not in config:
        return

    for module, functions in plugins.items():
        if module not in config['plugins']:
            continue
        for f in functions:
            if f in config['plugins'][module]:
                config['plugins'][module].remove(f)
        if len(config['plugins'][module]) == 0:
            del config['plugins'][module]

    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2, sort_keys=True)


@cli.command()
@click.pass_context
def run(ctx):
    """run the daemon"""
    pid_file = ctx.parent.params['pidfile']
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    config_file = ctx.parent.params['config']
    from sentinellad.daemon import Tourbillon
    ag = Tourbillon(config_file)
    ag.run()


def main():
    cli(prog_name='sentinellad', standalone_mode=False)

if __name__ == '__main__':
    if __package__ is None:
        path = os.path.dirname(os.path.dirname(os.path.dirname(
                               os.path.abspath(__file__))))

        sys.path.append(path)
    main()
