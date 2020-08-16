import sys
import numpy as np

INPUT_FILE = sys.argv[1]

num_active_msgs_receiver = []
num_active_msgs_sender = []
num_active_senders_per_receiver = []
num_active_receivers_per_sender = []
num_ooo_bytes = []

max_active_msgs_receiver = 0
max_active_msgs_sender = 0
max_active_senders_per_receiver = 0
max_active_receivers_per_sender = 0
max_ooo_bytes = 0

with open(INPUT_FILE) as f1:
    for line in f1:
        line_str = line.split()
        num_active_msgs_receiver.append(int(line_str[2]))
        if(int(line_str[3]) > max_active_msgs_receiver):
            max_active_msgs_receiver = int(line_str[3])
        
        num_active_msgs_sender.append(int(line_str[4]))
        if(int(line_str[5]) > max_active_msgs_sender):
            max_active_msgs_sender = int(line_str[5])
        
        num_active_receivers_per_sender.append(int(line_str[6]))
        if(int(line_str[7]) > max_active_receivers_per_sender):
            max_active_receivers_per_sender = int(line_str[7])
        
        num_active_senders_per_receiver.append(int(line_str[8]))
        if(int(line_str[9]) > max_active_senders_per_receiver):
            max_active_senders_per_receiver = int(line_str[9])
        
        num_ooo_bytes.append(int(line_str[10]))
        if( int(line_str[11]) >  max_ooo_bytes):
            max_ooo_bytes = int(line_str[11])

print("Num active msgs per receiver")
print("Mean: ", sum(num_active_msgs_receiver)/len(num_active_msgs_receiver))
print("Median: ", np.percentile(num_active_msgs_receiver,50))
print("99%: ", np.percentile(num_active_msgs_receiver,99))
print("max: ", max_active_msgs_receiver)

print("Num active msgs per sender")
print("Mean: ", sum(num_active_msgs_sender)/len(num_active_msgs_sender))
print("Median: ", np.percentile(num_active_msgs_sender,50))
print("99%: ", np.percentile(num_active_msgs_sender,99))
print("max: ", max_active_msgs_sender)

print("Num active receivers per sender")
print("Mean: ", sum(num_active_receivers_per_sender)/len(num_active_receivers_per_sender))
print("Median: ", np.percentile(num_active_receivers_per_sender,50))
print("99%: ", np.percentile(num_active_receivers_per_sender,99))
print("max: ", max_active_receivers_per_sender)

print("Num active senders per sender")
print("Mean: ", sum(num_active_senders_per_receiver)/len(num_active_senders_per_receiver))
print("Median: ", np.percentile(num_active_senders_per_receiver,50))
print("99%: ", np.percentile(num_active_senders_per_receiver,99))
print("max: ", max_active_senders_per_receiver)

print("Num ooo bytes")
print("Mean: ", sum(num_ooo_bytes)/len(num_ooo_bytes))
print("Median: ", np.percentile(num_ooo_bytes,50))
print("99%: ", np.percentile(num_ooo_bytes,99))
print("max: ", max_ooo_bytes)

