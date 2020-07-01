import sys
import time
import json
import logging

from Scanner.configuration import *

class Ping:

    @staticmethod
    def send_ping_for_subnet(input_json_file):
        try:
            # Import modules
            import subprocess
            import ipaddress
            import nmap

            start = time.time()
            print ("Start send ping for subnet")
            #The r before is to cancel \
            with open(input_json_file, 'r') as json_file:
                data = json.load(json_file)

                global count, target_json, exclude_json
                count = 0
                segment_json = (data["segment"])

                #To know the number of the subnets in the file
                data_json_file = {}
                data_json_file[''] = []

                logging.info("INFO: The objects from the file is: %s" % (len(segment_json)))
                while count < (len(segment_json)):
                    target_json = (data["segment"][count]["target"])
                    exclude_json = (data["segment"][count]["exclude"])

                    logging.info("INFO: Now, It is on the - %s - subnet chain" % count)
                    logging.info("INFO: There are %d subnet chain in the input file" % (len(segment_json)))
                    logging.info("INFO: The ip that it looks at is %s, should be in CIDR format (ex. 192.168.1.0/24)" % target_json)
                    net_addr = (target_json)
                    # Prompt the user to input a network address
                    # net_addr = input("Enter a network address in CIDR format (ex.192.168.1.0/24): ")
                    # Create the network
                    ip_net = ipaddress.ip_network(net_addr)
                    # Get all hosts on that network
                    all_hosts = list(ip_net.hosts())
                    # Configure subprocess to hide the console window
                    info = subprocess.STARTUPINFO()
                    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    info.wShowWindow = subprocess.SW_HIDE

                    #packets = data["segment"][count]["packets"]
                    #packets_string = str(packets)
                    #print("packet: %s" % packets_string )
                    print("Starting the scan")
                    segment_list = exclude_json
                    logging.info("INFO: The subnet that nmap will do: " + target_json)
                    nmScan = nmap.PortScanner()  # initialize the port scanner
                    nmScan.scan(hosts=target_json, arguments='-v -sP --exclude ' + Ping.exclude(segment_list))

                    #If i want to print it in a output file
                    flag = True
                    count += 1
                    Ping.write_to_json_file(nmScan, data_json_file, flag, segment_json)

                    logging.info("INFO: All the hosts are %s" % (nmScan.all_hosts()))
                    logging.info("INFO: Finished to write the ping scanning to the json file")

            end = time.time()
            logging.info("INFO: The function time is: %s" % (end - start))

        except (FileNotFoundError, IOError):
            logging.error("ERROR: Wrong file or file path")
        except ValueError:
            logging.error("ERROR: There is a problem in the input Json file")
        except:
            logging.error("ERROR: Unexpected error:", sys.exc_info()[0])
            raise

    @staticmethod
    def write_to_json_file(nmScan, data_json_file, flag, segment_json):
        global outfile
        with open(output_json_file, "a+", newline="\n") as outfile:
            for host in nmScan.all_hosts():
                if nmScan[host].state() == "down":
                    status = False
                elif nmScan[host].state() == "up":
                    status = True
                else:
                    status = "Undefined"
                data_json_file[''].append({
                    'ip': host,
                    'ping': True,
                    'port': None,
                    'status_ping': status
                })
            if flag == True and (count == (len(segment_json))):
            #if __name__ == "__main__":
                print("write to the sample file")
                print(data_json_file)
                json.dump (data_json_file, outfile, indent=4, sort_keys=True)
                logging.info("INFO: Finished write to json file ping class")
            else:
                print("Not write anything to a sample file")
                #json.dump (data_json_file, outfile, indent=4, sort_keys=True)
                logging.info("PAY ATTENTION: INFO: Finished write to json file ping class")

    @staticmethod
    def exclude(segment_list):
        exclude_string = str(segment_list)
        logging.info("INFO: There are %d chains/ips are off" % len(segment_list))
        i = 0
        new_string = ""
        while i < (len(segment_list)):
            if i == 0:
                new_string += str(segment_list[i])
            else:
                new_string += ("," + str(segment_list[i]))
            i += 1
        logging.info("INFO: The exclude ips are: %s" % new_string)
        return new_string



