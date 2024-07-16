import schedule
import time
import configparser
import os
from heartbeat import sync
from trivyscan import trivy_scan
from svnscan import svn_log
from pmdscan import pmd_scan
from rosylnatorscan import rosylnator_scan
from spotbugsscan import spotbugs_scan
from insiderscan import insider_scan
from logfile import setup_logger

script_path = os.path.abspath(__file__)
script_filename = os.path.basename(script_path)
logging = setup_logger()


config = configparser.ConfigParser()
config.read('svn_config.ini')

heartbeat_api_interval = str(config['LOCAL']['heartbeat_api_interval'])
svn_api_interval = str(config['LOCAL']['svn_api_interval'])
trivy_api_interval = str(config['LOCAL']['trivy_api_interval'])
pmd_api_interval = str(config['LOCAL']['pmd_api_interval'])

try:
    # schedule.every(10).hours.do(sync)
    # schedule.every(20).seconds.do(svn_log)
    # schedule.every(30).seconds.do(trivy_scan)
    # schedule.every(40).seconds.do(pmd_scan)
    # schedule.every(40).seconds.do(rosylnator_scan)
    # schedule.every(40).seconds.do(spotbugs_scan)
    # schedule.every(40).seconds.do(insider_scan)

    # schedule.every(int(heartbeat_api_interval)).minutes.do(sync)
    # schedule.every(int(svn_api_interval)).minutes.do(svn_log)
    # schedule.every(int(trivy_api_interval)).minutes.do(trivy_scan)
    # schedule.every(int(pmd_api_interval)).minutes.do(pmd_scan)
    # You can schedule jobs with different intervals as needed
    # For example:
    # schedule.every().hour.do(job)
    # schedule.every().day.at("10:30").do(job)

    logging.info(script_filename + ' - Jobs started')
    while True:
        schedule.run_pending()
        time.sleep(5)
        # input('press any key to continue')

except Exception as e :
    logging.info(f'got error {e}')
    