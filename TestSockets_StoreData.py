# -*- coding: utf-8 -*-
"""
Created on Tue Mar 31 21:51:43 2015

@author: Isaiah


This program is a simple packet sniffer. It will sniff packets and display
important packet information.
"""

"""
NOTES:
    
    to get the throughput we can have a server running which our program will bind to and
    send a file, we measure the time for it and that will give us the RTT. Also we can store the data
    so that we can then filter through it according to the user. Need to calculate the average datagram size
    as well as the diameter(TTL window) of the network.
    
    
"""

import socket
import sys
from struct import *
import re

def main() :
    sniff_packets()
    
"""
Sniff_Packets is a funtion that will create a socket and then run the necessary while loops for the 
rest of the program to run effectively, It is the main method calling helper methods. Everything will
run from this single parent function
"""
def sniff_packets():
    #create all the list that will contain the packets, segragated by protocols
    packet_List = []
    TCP_List = []
    UDP_List = []
    ICMP_List = []
    IGMP_List = []
    Other_List = []
    #grab the name of the host by making this call:getHostbyname()
    HOST = socket.gethostbyname(socket.gethostname())
    #creation of the socket to be used throughout the program
    try :        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print 'Successfully Created Raw Socket!\n'
        #bind the host ot an open port
        s.bind((HOST, 0))
     
        #Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        #receive all packages
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print "\nPacket previews will be displayed, after sniffing begins, press CTRL-C when ready to stop sniffing.\n"
        raw_input('Press Enter to continue')
        #loop that will print a small preview of the IP header for the user to see and capture the packets        
        while True:
            #receive the data packets of up to size 65565
            packet = s.recvfrom(65565)
            #take the packet data from the tuple provided from call recvfrom which contains (packet, sourde Address)
            packet = packet[0]
            #allows the user to preview the Ip header info and help in choosing when to stop
            IP_preview(packet)
            #store every packet being sniffed in the appropriate list which will be later placed in a dictionary
            store_data(packet, packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List)
    #exception to deal with issues in creation of the socket
    except socket.error, msg:
        print 'Socket could not be created. Error code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    #exception to catch the command CTRL-C and continue with the program
    except KeyboardInterrupt :
        print "No More Sniffing!"

    #print "Number of packets {}, Number of TCP {}".format(len(packet_List), len(TCP_List))
    
    #assign to a dictionary all the list of different protocols
    dict_Packets = create_Dict(packet_List, TCP_List, UDP_List, ICMP_List, IGMP_List, Other_List)    
    #initialize a counter to keep track of how many packets to print at a time and assign a limit    
    keepCount = 0
    limit = 10
    #loop that will print the captured data and give the user flexibility in accessing the data
    while True:
        #get an option from the user and display the menu
        choice = show_Menu()
        #if and else calls that function as a switch:case for the multiple options
        #print all the packets captured in order
        if(choice == '0'):
            All = dict_Packets['ALL']
            for i in range(0, len(All)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(All[i])
                    if(protocol == 6):
                        print_TCP(All[i], iphl)
                    elif(protocol == 17):
                        print_UDP(All[i], iphl)
                    elif(protocol == 1):
                        print_ICMP(All[i], iphl)
                    elif(protocol == 2):
                        print_IGMP(All[i], iphl)
                    else:
                        print "\nUnparsed procotol found!\n"
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the TCP packets
        elif(choice == '1'):
            tcp = dict_Packets['TCP']
            for i in range(0, len(tcp)):
                if(keepCount <= limit):                
                    iphl, protocol = print_IP(tcp[i])
                    print_TCP(tcp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the UDP packets
        elif(choice == '2'):
            udp = dict_Packets['UDP']
            for i in range(0, len(udp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(udp[i])
                    print_UDP(udp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the ICMP packets    
        elif(choice == '3'):
            icmp = dict_Packets['ICMP']
            for i in range(0, len(icmp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(icmp[i])
                    print_ICMP(icmp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print only the IGMP packets
        elif(choice == '4'):
            igmp = dict_Packets['IGMP']
            for i in range(0, len(igmp)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(igmp[i])
                    print_IGMP(igmp[i], iphl)
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        #print all other protocols found
        elif(choice == '5'):
            other = dict_Packets['OTHER']
            for i in range(0, len(other)):
                if(keepCount <= limit):
                    iphl, protocol = print_IP(other[i])
                    print "\nUnparsed protocol found\n!"
                else:
                    raw_input("Press Enter to see next "+ str(limit) +" entries.")
                    keepCount = 0
                keepCount += 1
        elif(choice == '6'):
            break
        else:
            print "Invalid option!\n"
        

    #server/client code will go here and determine throughput    
    print "Successfully implemented the First Part!"
    #print out the maxsize and the average of the data session    
    max_total(packet_List)
    
    # disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()    

"""
This function will print the IP header information, it does the unpacking and deciphering of the data
It only reads the first 20 bytes which include the header
"""
def print_IP(packet):
    ipHeader = packet[0:20]
    #unpack the data found in the ip datagram, there are 10 items
    ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
    version_IPHeaderLength = ipDatagram[0]
    ipVer = version_IPHeaderLength >> 4
    #0xF is 15 and the '&' operand copies a bit to the result if it exists
    #in both operands            
    ipHeaderLength = version_IPHeaderLength & 0xF
    #
    iphl = ipHeaderLength * 4
    TOS = ipDatagram[1]            
    totalLength = ipDatagram[2]
    ID = ipDatagram[3]
    flags = ipDatagram[4]
    fragments = ipDatagram[4] & 0x1FFF
    #time to live
    ttl = ipDatagram[5]
    #transport protocol
    protocol = ipDatagram[6]
    checksum = ipDatagram[7]
    #source and destination ip addresses
    sourceIP = socket.inet_ntoa(ipDatagram[8])
    destinationIP = socket.inet_ntoa(ipDatagram[9])
    
    print "\n\nVersion: \t\t" + str(ipVer)
    print "Header Length: \t\t" + str(iphl) + " bytes"
    #print "Type of Service: \t" + TypeOfService(TOS)
    print "Length:\t\t\t" + str(totalLength)
    #print "ID:\t\t\t" + str(hex(ID)) + '(' +str(ID) + ')'
    print "Flags:\t\t\t" + getFlags(flags)
    #print "Fragment Offset:\t" + str(fragments)
    #print "TTL:\t\t\t" + str(ttl)
    print "Protocol:\t\t" + getProtocol(protocol)
    #print "Checksum:\t\t" + str(checksum)
    print "SourceIP:\t\t" + sourceIP
    print "DestinationIP:\t\t" + destinationIP
    
    #will be used to find where the Transport information begins in methods calling print_IP()
    return iphl, protocol
"""
This function prints the TCP data, it unpacks and deciphers the header data
"""
def print_TCP(packet, iphl):
    tcp_header = packet[iphl:iphl+20]
    #unpack the tcp header information                
    tcph = unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    destination_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    
    #extract all the flags from the tcp header
    getTCPFlags(tcph[4], tcph[5])     
    #the congestion window
    conge_win = tcph[6]
    
    print 'Source Port {}, Destination Port {}, sequence {}'.format(source_port, destination_port, sequence)
    print 'Acknowledgement {}, TCP Length {}, Congestion Window: {}'.format(acknowledgment, tcph_length*4, conge_win)
    
    header_size = iphl + tcph_length * 4
    data_size = len(packet) - header_size
    data = packet[header_size:]  

"""
This function prints the UDP data, it unpackes and deciphers the UDP header data
"""
def print_UDP(packet, iphl):
    udpl = 8
    udp_header = packet[iphl:iphl+udpl]
    #unpack the udp header which is much smaller than TCP
    udph = unpack('!HHHH', udp_header)
    #take the wanted information and assing it to variables
    source_port = udph[0]
    destination_port = udph[1]
    length = udph[2]
    checksum = udph[3]
    
    print 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port)
    print 'length: {}, checksum: {}'.format(length, checksum)                
    #not used curretnly but may be useful for some future tasks, contains the data and header_size
    header_size = iphl + udpl
    data = packet[header_size:]

"""
This function prints the ICMP data, it unpacks and deciphers the ICMP header data
"""
def print_ICMP(packet, iphl):
    icmpl = 8
    icmp_header = packet[iphl:iphl+icmpl]
    #unpack the ICMP header which is only 4bytes
    icmp = unpack('!BBHHH',icmp_header)
    icmp_type = icmp[0]
    icmp_code = icmp[1]
    icmp_identifier = icmp[3]
    icmp_sequence = icmp[4]
    icmp_checksum = icmp[2]
    
    print "Type: {}, Code: {}, Checksum: {}".format(icmp_type, icmp_code, icmp_checksum)
    print "Identifier: {}, Sequence: {}".format(icmp_identifier, icmp_sequence)
"""
This function prints the IGMP data, it unpacks and deciphers the IGMP header data
"""
def print_IGMP(packet, iphl):
    igmpl = 8
    igmpl_header = packet[iphl:iphl+igmpl]
    #unpack the IGMP header information
    igmp = unpack('!BBHHH',igmpl_header)
    igmp_type = igmp[0]
    igmp_MaxTime = igmp[1]
    igmp_checksum = igmp[2]
    
    print "Type: {}, Max Response Time: {}".format(igmp_type, igmp_MaxTime)

"""
Function that displays the menu for the user, offering multiple options when viewing
the captured and stored data packets
"""
def show_Menu():
    numbers = [0,1,2,3,4,5,6]
    options = ['ALL','TCP','UDP','ICMP','IGMP','OTHER','EXIT']
    print "Select one of the following\n"
    for i in range(0, len(numbers)):
        if(i == len(numbers)-1):
            print "{}:{}".format(numbers[i], options[i])
        else:
            print "{}:Display {}".format(numbers[i], options[i])
    return raw_input("What would you like to do next?\n")

"""
This function just creates the dictionary to store the different protocols we
want to segregate
"""
def create_Dict(ALL, TCP, UDP, ICMP, IGMP, Other):
    #initialize an empty dictionary and fill it with the options/lists we want    
    dict_Packets = {}
    dict_Packets["ALL"] = ALL
    dict_Packets["TCP"] = TCP
    dict_Packets["UDP"] = UDP
    dict_Packets["ICMP"] = ICMP
    dict_Packets["IGMP"] = IGMP
    dict_Packets["OTHER"] = Other
    
    return dict_Packets

"""
This Function will only print a small preview of the Ip header from the captured packets
so that the user can see live what is being captured. It will be stored and later be able to
navigate through the data dynamically depending on user choices
"""
def IP_preview(packet):
            
            ipHeader = packet[0:20]
            #unpack the data found in the ip datagram, there are 10 items
            ipDatagram = unpack("!BBHHHBBH4s4s",ipHeader)
            version_IPHeaderLength = ipDatagram[0]
            ipVer = version_IPHeaderLength >> 4
            #0xF is 15 and the '&' operand copies a bit to the result if it exists
            #in both operands            
            ipHeaderLength = version_IPHeaderLength & 0xF
            #
            iphl = ipHeaderLength * 4
            totalLength = ipDatagram[2]            
            #transport protocol
            protocol = ipDatagram[6]
            sourceIP = socket.inet_ntoa(ipDatagram[8])
            destinationIP = socket.inet_ntoa(ipDatagram[9])
            
            print "\n\nVersion: \t\t" + str(ipVer)
            print "Header Length: \t\t" + str(iphl) + " bytes"
            print "Length:\t\t\t" + str(totalLength)
            print "Protocol:\t\t" + getProtocol(protocol)
            #print "SourceIP:\t\t" + sourceIP
            #print "DestinationIP:\t\t" + destinationIP
            
            #this will be used to find the max and average size of the packets captured
            return totalLength
            
"""
Funtion that will add all the total lenghts and keep track of the largest packet size
This will return the largest packet and the total cumulative length of all the packets
"""         
def max_total(packetList):

    totalsize = 0    
    maxsize = 0

    for i in range(0, len(packetList)):
        ipdatagram = packetList[i]
        ipdata = ipdatagram[:20]        
        ipheader = unpack("!BBHHHBBH4s4s",ipdata)
        length = ipheader[4]
        totalsize += length
        if(maxsize<length):
            maxsize = length
            
    average = totalsize/len(packetList)
            
    print "The Maximum sized packet is: {}\n".format(maxsize)
    print "The Average packet size for this session is: {}\n".format(average)
            
"""
This function is the one that stores the packets being sniffed. As they are sniffed the IP header
is unpacked and the protocol checked so that it can be filtered and be placed into the
appropriate list which will later be added to a dictionary for easy navigation    
""" 
def store_data(packet, ALL, TCP, UDP, ICMP, IGMP, Other):
     """
     Will be using a list to store all similar protocols(TCP,UDP,ICMP)
     Each list will be stored in a dictionary where the key is the protocol
     For time being will only use top four seen protocols and a default used for all others
     The data will be stored within a list structure will look as below
     Dict = {'protocol':[[packet data], [packet data], [packet data]]...]}
     """
     IpData = packet[:20]
     ipDatagram = unpack("!BBHHHBBH4s4s", IpData)
     ALL.append(packet)
     protocol = ipDatagram[6]
     if(protocol == 6):
         TCP.append(packet)
     elif(protocol == 17):
        UDP.append(packet)
     elif(protocol == 1):
         ICMP.append(packet)
     elif(protocol == 2):
         IGMP.append(packet)
     else:
         Other.append(packet)
    
    
#get time of service - 8bits    
def TypeOfService(data):
    #set up the dictionaries that will contain the possible options
    precedence = {0:"Routine", 1:"Priority", 2:"Immediate", 3:"Flash", 4:"Flash Override", 5:"CRITIC/ECP", 6:"Internetwork Contril", 7:"Network Control"}
    delay = {0:"Normal delay", 1:"Low delay"}
    throughput = {0:"Normal Throughput", 1:"High Throughput"}
    reliability = {0:"Normal reliability", 1:"High reliability"}
    cost = {0:"Normal monetary cost", 1:"Minimize monetary cost"}
    
    #D->delay, T->throughput, R->reliability, M->monetary cost
    #the shift done by '>>=' is a bit operator that takes two binary strings and copies any that match
    #while the rest are all set to 0s.
    #0x10 -> 16, 0x8 -> 8, 0x4 ->4, 0x2 -> 2
    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1
    #string to format the output with a new line and three tabs
    tabs = '\n\t\t\t'
    TimeOfService = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TimeOfService

#returns the flag options for the IP header in a string format for easy printing    
def getFlags(data):
    #dictionaries with available options initialized
    flagR = {0:"0-Reserved Bit"}
    flagDF = {0:"0-Fragment if Necessary", 1:"1-Do Not Fragment"}
    flagMF = {0:"0-Last Fragment", 1:"1-More Fragments"}
    
    #bit wise operator used to shift decimals
    #0x8000 is 10000000 00000000
    #0x4000 is 01000000 00000000
    #0x2000 is 00100000 00000000
    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13
    #string to format the output
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags
#function that returns the protocol used at the transport layer
def getProtocol(data):
    #open file containing all possible protocols
    protocolFile = open('Protocols.txt', 'r')
    #reads the data in opened file
    protocolData = protocolFile.read()
    #returns all strings that match the patter described, \n + data + ending character
    protocol = re.findall(r'\n' + str(data) + ' (?:.)+\n', protocolData)
    #finds matching protocol on file and returns if one is found
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(data), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No Such Protocol Found"
        
def getTCPFlags(reserved, flags) :
    
    #reserved flags
    NS_flag = reserved & 0x1
    
    #congestion Window Reduced
    CWR_flag = flags >> 7
    #ECN-Echo, if SYN = 1 TCP peer is ECN capable, if SYN = 0 packet with congestion received
    ECE_flag = flags >> 6 & 0x1
    #indicates that the Urgent pointer field is significant
    URG_flag = flags >> 5 & 0x1
    #acknowledgement field is significant
    ACK_flag = flags >> 4 & 0x1
    #push function, asks to push the buffered data to the received
    PSH_flag = flags >> 3 & 0x1
    #reset the connection
    RST_flag = flags >> 2 & 0x1
    #synchronize sequence numbers
    SYN_flag = flags >> 1 & 0x1
    #no more data coming
    FIN_flag = flags & 0x1
    
    print "NS: {}\nCWR: {}\nECE: {}\nURG: {}\nACK: {}".format(NS_flag, CWR_flag, ECE_flag, URG_flag, ACK_flag)
    print "\nPSH: {}\nRST: {}\nSYN: {}\nFIN: {}\n".format(PSH_flag, RST_flag, SYN_flag, FIN_flag)
    
if __name__ == '__main__':
    main()