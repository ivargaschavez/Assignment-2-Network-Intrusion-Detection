import csv
import matplotlib.pyplot as plt
from collections import defaultdict
from TestNIDS import *


def parse_netflow():
    """Use Python's built-in csv library to parse netflow.csv and return a list
       of dictionaries. The csv library documentation is here:
       https://docs.python.org/3/library/csv.html"""
    with open('netflow.csv', 'r') as netflow_file:
        netflow_reader = csv.DictReader(netflow_file)
        netflow_data = list(netflow_reader)
        return netflow_data


def is_internal_IP(ip):
    """Return True if the argument IP address is within campus network"""
    s = ip.split('.')
    if s[0] == "128" and s[1] == "112":
        return True
    return False


def plot_bro(num_blocked_hosts):
    """Plot the list of the number of Bro blocked hosts indexed by T"""
    fig = plt.figure(figsize=(16,8))
    plt.plot(range(len(num_blocked_hosts)), num_blocked_hosts, linewidth=3)
    plt.xlabel("Threshold", fontsize=16)
    plt.ylabel("Number of Blocked Hosts", fontsize=16)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.title("Sensitivity of Bro Detection Algorithm", fontsize=16)
    plt.grid()
    plt.savefig("sensitivity_curve.png")


def detect_syn_scan(netflow_data):
    """TODO: Complete this function as described in readme.txt"""
    
    # Your code here
    percent_synonly = 0 # default value

    # Do not change this print statement
    print("\nPercent SYN-only flows: {} -> {}\n".format(
        percent_synonly, test_percent_synonly(percent_synonly)))


def detect_portscan(netflow_data):
    """TODO: Complete this function as described in readme.txt"""

    # Your code here
    synonly_knownbad = []           # default value
    synonly_NOTknownbad = []        # default value
    other_knownbad = []             # default value      
    other_NOTknownbad = []          # default value

    percent_knownbad = 0            # default value
    percent_synonly_knownbad = 0    # default value
    percent_synonly_NOTknownbad = 0 # default value

    # Do not change these statments
    print("Precent of TCP flows to known bad ports: {} -> {}".format(
        percent_knownbad, test_percent_knownbad(percent_knownbad)))
    print("Percent of SYN-only TCP flows to known bad ports: {} -> {}".format(
        percent_synonly_knownbad, test_percent_synonly_knownbad(percent_synonly_knownbad)))
    print("Percent of SYN-only TCP flows to other ports: {} -> {}\n".format(
        percent_synonly_NOTknownbad, test_percent_synonly_NOTknownbad(percent_synonly_NOTknownbad)))
    return synonly_knownbad, synonly_NOTknownbad, other_knownbad, other_NOTknownbad


def detect_malicious_hosts(netflow_data, synonly_knownbad, synonly_NOTknownbad, 
                           other_knownbad, other_NOTknownbad):
    """TODO: Complete this function as described in readme.txt"""

    # Your code here
    num_malicious_hosts = 0    # default value
    num_benign_hosts = 0       # default value
    num_questionable_hosts = 0 # default value
 
    # Do not change these print statments
    print("Number of malicious hosts: {} -> {}".format(
        num_malicious_hosts, test_num_malicious_hosts(num_malicious_hosts)))
    print("Number of benign hosts: {} -> {}".format(
        num_benign_hosts, test_num_benign_hosts(num_benign_hosts)))
    print("Number of questionable hosts: {} -> {}\n".format(
        num_questionable_hosts, test_num_questionable_hosts(num_questionable_hosts)))


class Bro:
    """TODO: complete this class to implement the Bro algorithm"""
    
    def __init__(self, threshold):
        # self.T is the threshold number of unique destination addresses from
        #     successful and/or failed connection attempts (depending on port)
        #     before a host is marked as malicious
        self.T = threshold
        
        # self.good_services is the list of port numbers to which successful connections 
        #     (SYN and ACK) should not be counted against the sender
        self.good_services = [80, 22, 23, 25, 113, 20, 70]

        # You may add additional class fields and/or helper methods here

    def run(self, netflow_data):
        """TODO: Run the Bro algorithm on netflow_data, returning a 
                 set of blocked hosts. You may add additional helper methods 
                 or fields to the Bro class"""
        blocked_hosts = set()

        for flow in netflow_data: # loop simulates an "online" algorithm 
            # Your code here

        # Do not change this return statement
        return blocked_hosts


def main():
    """Run all functions"""
    netflow_data = parse_netflow()
    detect_syn_scan(netflow_data)
    portscan_flows = detect_portscan(netflow_data)
    detect_malicious_hosts(netflow_data, *portscan_flows)
    num_blocked_hosts = [len(Bro(T).run(netflow_data)) for T in range(1, 121)]
    plot_bro(num_blocked_hosts)
    print("Bro sensitivity curve plotted")


if __name__=="__main__":
    main()
