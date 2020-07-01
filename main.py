from Scanner.configuration import *
from Scanner.scanning_main import *
from Scanner.PortScanning import *

import json
import _thread
import threading
import multiprocessing
import time
import os
import sys

def main():
    start = time.time ()
    timeout = 360
    if (os.path.exists(directory_input_json_file)):
        if len(os.listdir(directory_input_json_file)) > 0:
            for filename in os.listdir (directory_input_json_file):
                try:
                    filename = directory_input_json_file+filename
                    with open (filename, 'r') as check_if_json_file:
                        data = json.load (check_if_json_file)
                    print("The current input json file is:" + filename)

                    t1=threading.Thread(target=Ping.send_ping_for_subnet, args=(filename,))
                    t2=threading.Thread(target=PortScanning.port_scanning, args=(filename,))
                    t1.start()
                    t1.join(timeout)

                    t2.start()
                    t2.join(timeout)

                    print("Active Threads ", end = '')
                    print(threading.activeCount())
                    print("filename " + filename)
                    #Ping.send_ping_for_subnet(filename)
                    #PortScanning.port_scanning(filename)

                except ValueError as e:
                    logging.error("ERROR: The file %s in the directory is not a json format or json file" % filename)
                except:
                    print ("Unexpected error:", sys.exc_info ()[0])
        else:
            logging.error("ERROR: The directory is empty")
    else:
        logging.error("ERROR: The directory doesn't exist")

main()