from time import sleep

from sqlalchemy import create_engine

from qg_api.cfg import QG_DB_URI

engine = create_engine(QG_DB_URI)

def check_connection(engine, retries=10, delay=10):
    for _ in range(retries):
        try:
            engine.connect()
        except Exception as e:
            print('Connection failed with:\n{}'.format(e))
            sleep(delay)
        else:
            print('Connection successfull')
            return
    exit('Unable to connect to db.')


if __name__ == '__main__':
    check_connection(engine)
