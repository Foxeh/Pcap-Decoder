import dpkt
from kafka.client import KafkaClient
from kafka.producer import SimpleProducer

# Open Pcap    
f = open('test.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

pktCounter = 0

# Read and send to Kafka
for ts, buf in pcap:
    
    pktCounter += 1
    
    eth = dpkt.ethernet.Ethernet(buf)

    client = KafkaClient("192.168.150.254:9092")
    producer = SimpleProducer(client)
    
    print "Packet Number: %s" %(pktCounter)

    while True:
        producer.send_messages('pcap', eth)