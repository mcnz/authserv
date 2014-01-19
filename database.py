# encoding: utf-8

from logging import getLogger

from MySQLdb import connect as MySQLConnect

MYSQL_HOST  = '127.0.0.1'
MYSQL_USER  = ''
MYSQL_PASS  = ''
MYSQL_DB    = ''
MYSQL_TABLE = ''

class Database():

    logger = getLogger('database')

    def __enter__(self):
        self.logger.debug('Connecting to database...')
        self.db = MySQLConnect(MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB)
        self.logger.debug('Connected')
        self.cursor = self.db.cursor()
        return self

    def __exit__(self, type, value, traceback):
        self.logger.debug('Closing database...')
        self.cursor.close()
        self.db.close()
        self.logger.debug('Closed')

    def authkeyExists(self, authkey):
        self.cursor.execute('SELECT authkey FROM ' + MYSQL_TABLE + ' WHERE authkey = %s', (authkey,))
        return None is not self.cursor.fetchone()

    def insertAuthkey(self, playername, authkey):
        self.cursor.execute("DELETE FROM " + MYSQL_TABLE + " WHERE playername = %s", (playername,))
        self.cursor.execute("INSERT INTO " + MYSQL_TABLE + " VALUES (%s, %s, now())", (playername, authkey))
        self.db.commit()