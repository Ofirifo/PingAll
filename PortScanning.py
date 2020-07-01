from Scanner.configuration import *
from Scanner.scanning_main import Ping

import os
import threading
import sys
import time
import json
import logging

class PortScanning:
    logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

    @staticmethod
    def file_from_directory():
        import os
        if (os.path.exists(directory_input_json_file)):
            if len(os.listdir(directory_input_json_file)) > 0:
                for filename in os.listdir (directory_input_json_file):
                    try:
                        filename = directory_input_json_file+filename
                        with open (filename, 'r') as check_if_json_file:
                            data = json.load (check_if_json_file)
                        print("The current input json file is:" + filename)
                        PortScanning.port_scanning(filename)
                    except ValueError as e:
                        logging.error("ERROR: The file %s in the directory is not a json format or json file" % filename)
                    except TypeError:
                        logging.error("type error")
            else:
                logging.error("ERROR: The directory is empty")
        else:
            logging.error("ERROR: The directory doesn't exist")

    @staticmethod
    def port_scanning(input_json_file):
        try:
            # Import modules
            import subprocess
            import ipaddress
            import nmap

            global data, count, data_json_file, net_addr
            print("start port_scanning ")

            start = time.time()
            with open(input_json_file, 'r') as json_file:
                data = json.load(json_file)
                count = 0
                #To know the number of the subnets in the file
                data_json_file = {}
                data_json_file[''] = []
                logging.info("INFO: The Number of the objects you want to make ping and port scanning are: %d" % (len(data["manual"])))
                print("Checking number of subnets: %d" % len(data["manual"]))
                while count < (len(data["manual"])):
                    logging.info("INFO: Now, It run on the %s ip:" % count)
                    logging.info("INFO: The ip that it looks at is %s, should be in CIDR format (ex. 192.168.1.0/24)" % data["manual"][count]["target"])

                    net_addr = (data["manual"][count]["target"])
                    # Prompt the user to input a network address
                    # net_addr = input("Enter a network address in CIDR format (ex.192.168.1.0/24): ")
                    # Create the network
                    ip_net = ipaddress.ip_network(net_addr)
                    # Get all hosts on that network
                    all_hosts = list(ip_net.hosts())
                    # Configure subprocess to hide the console window
                    # info = subprocess.STARTUPINFO()
                    # info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    # info.wShowWindow = subprocess.SW_HIDE

                    ping_checking = str(data["manual"][count]["is_ping"])
                    PortScanning.is_ping(ping_checking)

                    port_checking = (data["manual"][count]["port"])
                    #Should be here.. because I use it in write to json & before as count=number
                    count += 1
                    PortScanning.is_port(port_checking)
                    logging.info("INFO: Finished to do portscanning and pingscanning to the ip")

            end = time.time()
            logging.info("INFO: The function time is: %s seconds" % (end - start))

        except (FileNotFoundError, IOError):
            logging.error("ERROR: Wrong file or file path")
        except ValueError:
            logging.error("ERROR: There is a problem in the input Json file")
        except:
            logging.error("ERROR: Unexpected error: (port scanning)", sys.exc_info()[0])
            raise

        print("Finished1")


    @staticmethod
    def write_to_json_file(nmScan, port_checking):
        try:
            with open(output_json_file, "a+", newline="\n", closefd=True) as outfile:
                hosts_list = [(x, nmScan[x]['status']['state']) for x in nmScan.all_hosts()]
                for host, status in hosts_list:
                    if not nmScan[host].all_protocols():
                        logging.error("ERROR: Cannot do nmap to this ip", end= ' ' + host)
                        break
                    for proto in nmScan[host].all_protocols():
                        port = int(port_checking)
                        if nmScan[host][proto][port]['state'] == "closed":
                            status = False
                        elif nmScan[host][proto][port]['state'] == "open":
                            status = True
                        else:
                            status = "Undefined"
                        data_json_file[''].append({
                            'ip': host,
                            'ping': False,
                            'port': port,
                            'status_port': status
                            })
                print(data_json_file)
                if (count == (len(data["manual"]))):
                    print("Print to the file (Finished all ports) -----------------------------------------------------")
                    logging.info("INFO: Now... It is writing to the ouput file")
                    json.dump(data_json_file, outfile, indent=4, sort_keys=True)
        except:
            print ("ERROR: Unexpected error: (write_to_json_file)", sys.exc_info ()[0])

    @staticmethod
    def is_ping(ping_checking):
        import nmap
        if ping_checking == 'True':
            logging.info("INFO: Started to doing ping to the ip you wanted")
            nmScan = nmap.PortScanner ()  # initialize the port scanner
            nmScan.scan (hosts=net_addr, arguments='-v -sP')
            logging.info("INFO: The ip of the ping function:" + net_addr)
            #Flag - if I want to print it
            flag = False
            t3 = threading.Thread(target=Ping.write_to_json_file, args=(nmScan, data_json_file, flag, net_addr))
            t3.start()
            t3.join()
        else:
            logging.warning("WARNING: Not required to the a ping scanning to the ip " + net_addr)
            pass

    @staticmethod
    def is_port(port_checking):
        import nmap
        if port_checking != 'None':
            count_port = 0
            #Convert in case of int to list
            if (type(port_checking) == int):
                temp = []
                temp.append(port_checking)
                port_checking = temp
                print("only one port in this ip port_checking_int" , end=' ')
                print(port_checking)
                logging.info("INFO: Started to doing port with the port and the ip you wanted")

            while count_port < (len(port_checking)):
                nmScan = nmap.PortScanner ()  # initialize the port scanner
                logging.info("INFO: The ip you wanted to do so is %s and the port you wanted to do so is %s" % (net_addr, str(port_checking[count_port])))
                nmScan.scan(hosts=net_addr, arguments='-v -p' + str(port_checking[count_port]))
                t4 = threading.Thread (PortScanning.write_to_json_file(nmScan, str(port_checking[count_port])))
                t4.start()
                t4.join()
                print("INFO: Finished writing command")
                print("number of ports in this ip %d" % count_port)
                count_port += 1

        else:
            logging.warning("WARNING: Not require Port Checking")
            pass

#PortScanning.file_from_directory()
#Ping.send_ping_for_subnet()