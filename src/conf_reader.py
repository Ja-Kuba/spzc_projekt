from configparser import ConfigParser, NoOptionError, NoSectionError
import os.path


class ConfReader:

    def __init__(self):
        pass

    @staticmethod
    def read_conf(ini_path):
        if not os.path.isfile(ini_path):
            raise FileNotFoundError(f'Ini file: \'{ini_path}\' does NOT exist')

        sniffer_conf = dict()
        trw_conf = dict()

        conf = ConfigParser()
        conf.read(ini_path)
        try:
            sniffer_conf['max_packets'] = int(conf.get('SNIFFER', 'max_packets'))

            trw_conf['Pd'] = float(conf.get('TRW_PROCESSOR', 'Pd'))
            trw_conf['Pf'] = float(conf.get('TRW_PROCESSOR', 'Pf'))
            trw_conf['theta0'] = float(conf.get('TRW_PROCESSOR', 'theta0'))
            trw_conf['theta1'] = float(conf.get('TRW_PROCESSOR', 'theta1'))
            trw_conf['oracle_source'] = str(conf.get('TRW_PROCESSOR', 'oracle_source'))
            trw_conf['local_network'] = str(conf.get('TRW_PROCESSOR', 'local_network'))
            trw_conf['stats_dump_period'] = int(conf.get('TRW_PROCESSOR', 'stats_dump_period'))

            return sniffer_conf, trw_conf

        except (NoOptionError, NoSectionError) as e:
            raise KeyError(f'Invalid ini "{ini_path}": {e}')
