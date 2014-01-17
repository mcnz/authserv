# encoding: utf-8

import logging

LOG_FILE        = 'authserv.log'
LOG_FMT         = '%(asctime)s %(name)-15s %(levelname)-7s %(message)s'
LOG_DATEFMT     = '%y-%m-%d %H:%M:%S'

def setupLogging(consolelevel=logging.INFO, logfile=LOG_FILE):
    '''
    sets up the logger such that:
      debug+   -> file
      info+    -> console
    '''
    logging.basicConfig(
        level       = logging.DEBUG,
        format      = LOG_FMT,
        datefmt     = LOG_DATEFMT,
        filename    = logfile,
        filemode    = 'w'
    )
    # log to console
    consolelog = logging.StreamHandler()
    consolelog.setLevel(consolelevel)
    consolelog.setFormatter(logging.Formatter(LOG_FMT, LOG_DATEFMT))
    logging.getLogger().addHandler(consolelog)