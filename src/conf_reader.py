from configparser import ConfigParser, NoOptionError, NoSectionError
import os.path

class ConfReader:
    
    def __init__(self):
        pass

    def readConf(self, ini_path):
        if not os.path.isfile(ini_path):
            raise FileNotFoundError(f'Ini file: \'{ini_path}\' does NOT exist')
        
        sniffer_conf = dict()
        trw_conf = dict()

        conf = ConfigParser()
        conf.read(ini_path)
        try:
            sniffer_conf['max_packets'] =  int(conf.get('SNIFFER', 'max_packets'))
   
            trw_conf['Pd'] =  float(conf.get('TRW_PROCESSOR', 'Pd'))
            trw_conf['Pf'] =  float(conf.get('TRW_PROCESSOR', 'Pf'))
            trw_conf['theta0'] =  float(conf.get('TRW_PROCESSOR', 'theta0'))
            trw_conf['theta1'] =  float(conf.get('TRW_PROCESSOR', 'theta1'))
            trw_conf['orcale_source'] =  str(conf.get('TRW_PROCESSOR', 'orcale_source'))
        
            return sniffer_conf, trw_conf

        except (NoOptionError, NoSectionError) as e:
            raise KeyError(f'Invalid ini "{ini_path}": {e}')
        



