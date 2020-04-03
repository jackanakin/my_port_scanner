import nmap
import threading
import time

nsList = []

class PortScannerThread (threading.Thread):
   def __init__(self, threadID, ip_address, port_range):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ip_address = ip_address
        self.port_range = port_range
   
   def run(self):
        #print("%s: %s" % ("Started " + self.ip_address, time.ctime(time.time())))
        ns = nmap.PortScanner()
        ns.scan(self.ip_address, self.port_range, '-v')
        
        # Get lock to synchronize threads
        threadLock.acquire()
        
        nsList.append({"ip": self.ip_address, "result": ns.csv()})

        # Free lock to release next thread
        threadLock.release()
        #print("%s: %s" % ("Finished " + self.ip_address, time.ctime(time.time())))

threadLock = threading.Lock()
threads = []

ip_listFile = open("ip_list.txt", "r")

for ip in ip_listFile:
    thread1 = PortScannerThread(1, ip, "1-65535")
    thread1.start()
    threads.append(thread1)

# Wait for all threads to complete
for t in threads:
    t.join()

print("Exiting Main Thread")
f = open("scan_result.txt", "w")

for ns in nsList:
    ip = ns["ip"].replace('\n', '')
    f.write("=================| " + ip + " |=================\n")
    for line in ns["result"]:
        f.write(line.replace('\n', ''))

f.close()

