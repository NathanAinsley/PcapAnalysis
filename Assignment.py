# -*- coding: utf-8 -*-
"""
Created on Sun May  8 17:00:04 2022

@author: natha
"""

import dpkt
from dpkt.tcp import TCP
import socket
import matplotlib.pyplot as plt
from collections import Counter
from random import randint
import pandas as pd
import datetime
import csv
import tkinter as tk
import tkinter.filedialog as fd


def BytesOverTimeGraph(file):
    f = open(file, "rb")
    pcap = dpkt.pcap.Reader(f)
    size=[]
    time=[]
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if type(ip.data) == TCP :
            tcp = ip.data
            size.append(len(tcp.data))
            time.append(datetime.datetime.fromtimestamp(ts))
    f.close()
    pd_size=pd.Series(size).astype(int)
    pd_times=pd.to_datetime(pd.Series(time).astype(str),errors='coerce')
    data_frame = pd.DataFrame({"Bytes":pd_size,"Times":pd_times})
    data_frame = data_frame.set_index('Times')
    data_frame2 = data_frame.resample('2S').sum()
    plt.plot(data_frame2.index,data_frame2['Bytes'])
    plt.xlabel("Time")
    plt.xticks(rotation=90)
    plt.ylabel("Size of Data")
    plt.title(f"{file} Packet Size over Time")
    figfile = RemovePcapType(file)+"_SizeLine.PNG"
    Save_Wipe(figfile)
    
def BarIPChart(file):
    f = open(file, "rb")
    pcap = dpkt.pcap.Reader(f)
    srcIP=[]
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if type(ip.data) == TCP :
            source_ip = socket.inet_ntoa(ip.src)
            srcIP.append(source_ip)
    f.close()
    cntr = Counter()
    for ip in srcIP:
        cntr[ip] += 1
    xD = []
    yD = []
    for ip, count in cntr.most_common():
        xD.append(ip)
        yD.append(count)
    colours = []
    for i in range(len(xD)):
        colours.append('#%06X' % randint(0, 0xFFFFFF))
    plt.bar(xD,yD,width=0.8,color=colours)
    plt.xlabel("Source IP")
    plt.ylabel("Amount of Packets")
    plt.title(f"{file} Amount of packets from Src IP")
    figfile = RemovePcapType(file)+"_bar.PNG"
    Save_Wipe(figfile)
def Save_Wipe(figfile):
    plt.savefig(fname=figfile,format='png')
    plt.clf()
    plt.cla()
def RemovePcapType(file):
    size=len(file)
    mod_string=file[:size-5]
    return mod_string

def portcounter(file):
    f = open(file, "rb")
    pcap = dpkt.pcap.Reader(f)
    SourcePort = []
    DestinationPort = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if type(ip.data) == TCP :
            tcp = ip.data
            sport = tcp.sport
            dport = tcp.dport
            SourcePort.append(sport)
            DestinationPort.append(dport)
    f.close()
    cntr = Counter()
    cntr2 = Counter()
    for sport in SourcePort:
        cntr[sport] += 1
    for dport in DestinationPort:
        cntr2[dport] += 1
    sfigfile = RemovePcapType(file)+"_SourcePortTable.CSV"
    with open (sfigfile,'w',newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter = ',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['Port', 'Count'])
        for port, count in cntr.most_common():
            writer.writerow([port, count])
    dfigfile = RemovePcapType(file)+"_DestinationPortTable.CSV"
    with open (dfigfile,'w',newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter = ',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['Port', 'Count'])
        for port, count in cntr2.most_common():
            writer.writerow([port, count])

    
def main():
    root = tk.Tk()
    filez = fd.askopenfilenames(parent=root, title='Choose a file')
    root.withdraw()
    print(filez)
    for file in filez:
        portcounter(file)
        BarIPChart(file)
        BytesOverTimeGraph(file)
    print('Graphs and tables created in same folder as files selected')
main()