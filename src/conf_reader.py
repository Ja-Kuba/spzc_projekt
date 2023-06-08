from configparser import ConfigParser
import os.path

class ConfReader:
    
    def __init__(self, ini_path):
        self.db_connstr = ''
        self.host_name = ''
        self.__readConf(ini_path)

        self.printConf()

    def __readConf(self, ini_path):
        if not os.path.isfile(ini_path):
             exit(f'Ini file: \'{ini_path}\' does NOT exist')
        
        conf = ConfigParser()
        conf.read(ini_path)
        try:
            self.sniffer_conf['max_packets'] =  conf.get('SNIFFER', 'max_packets')
   
            self.trw_conf['Pd'] =  conf.get('TRW_PROCESSOR', 'Pd')
            self.trw_conf['Pf'] =  conf.get('TRW_PROCESSOR', 'Pf')
            self.trw_conf['theta0'] =  conf.get('TRW_PROCESSOR', 'theta0')
            self.trw_conf['theta1'] =  conf.get('TRW_PROCESSOR', 'theta1')
            self.trw_conf['orcale_source'] =  conf.get('TRW_PROCESSOR', 'orcale_source')
        
        except Exception as e:
            exit('ini error: ' + str(e))



