# Firewall Log Review / Log parsing
The purpose of this lab is to understand how to go through and parse log files. Understanding how to parse log files is an essential skill for any cybersecurity professional. Whether retrieving logs from an Apache server or a Windows computer system, the ability to effectively parse these logs is crucial. This skill is applicable to virtually any logging format on any server you may encounter. Key techniques include using tools like grep to extract specific data, employing the -v option to filter out unwanted information, utilizing cut to isolate specific fields, and performing basic mathematical operations on the data. Mastering these techniques ensures you can efficiently analyze and interpret log files in various environments.

## Environment and setup
This lab is part of the Antisyphon Training SOC Core Skills course with John Strand. Visit [Antisyphon](https://www.antisyphontraining.com/) for more information.
<br>
<br>
Before reviewing the logs, cd into the correct directory. Install r-base-core for some mathematical computations and data analysis.
```
cd /mnt/c/IntroLabs
sudo apt-get update
sudo apt install r-base-core --fix-missing
```
<br>
<br>

## Methodology
### 1. Initial log review
```
less ASA-syslogs.txt
```
![ASAlogs](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F1.png?raw=true)
<br>
This is a lot of information! The goal is to get to the point where I can start to understand and get some passable data. 
<br>
The first thing I see is that 24.230.56.6 is getting a lot of traffic. This is just a local gateway, so it is of not interest to me. Press *q* to quit.
<br>
<br>

### 2. Performing grep on suspect IP address and clearing out the local gateway entries
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | less
```
![grep](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F2.png?raw=true)
<br>
<br>

### 3. More clean up
I don’t necessarily care about all the different fields. I focus on the closed connections (FIN) and pull just specific fields out of the data to clean it up. I use *cut* with the -d switch to tell cut the delimiter is a space. Then, I specify the fields I am interested in.
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | grep FIN | cut -d ' ' -f 1,3,4,5,7,8,9,10,11,12,13,14
```
![grepFIN](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F3.png?raw=true)
<br>
Notice that the suspect IP is just communicating with two IP addresses again and again.
<br>
<br>

### 4. Analyzing those specific IPs
First, I look at the connections with 13.107.237.38. I only want to see data from that IP address.
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | grep FIN | grep 13.107.237.38 | cut -d ' ' -f 1,3,4,5,7,8,9,10,11,12,13,14
```
![IP1](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F4.png?raw=true)
<br>
I notice that the bytes are kind of close to eachother.
<br>
<br>

There are also a lot of connections from 18.160.185.174 as well, so I focus in on that IP address.
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | grep FIN | grep 18.160.185.174 | cut -d ' ' -f 1,3,4,5,7,8,9,10,11,12,13,14
```
![IP2](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F5.png?raw=true)
<br>
I see a pattern with the bytes field.
<br>
<br>

### 5. Bytes field
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | grep FIN | grep 18.160.185.174 | cut -d ' ' -f 14
```
![byte](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F6.png?raw=true)
<br>
<br>

### 6. Running bytes through a mathematical formula
This command asks for the minimum/maximum, the mean, the standard deviation, and the variance.
```
grep 192.168.1.6 ASA-syslogs.txt | grep -v 24.230.56.6 | grep FIN | grep 18.160.185.174 | cut -d ' ' -f 8,14 | tr : ' ' | tr / ' '  | cut -d ' ' -f 4 | Rscript -e 'y <-scan("stdin", quiet=TRUE)' -e 'cat(min(y), max(y), mean(y), sd(y), var(y), sep="\n")'
```
![math](https://github.com/trixiahorner/firewall_log_review/blob/main/images/F7.png?raw=true)
<br>
- Minimum: 1816
- Maximum: 1848
- Mean: 1829.805
- SD: 12.20163
- Variance: 151.33
<br>
This is a beacon! This regularity in the intervals, with minimal deviation, is a strong indicator of a beacon, which is often used by malware for periodic communication with a C2 server.
<br>

# Conclusion
The identification of beaconing behavior through log analysis exemplifies the importance of these skills. The narrow range between minimum and maximum intervals, coupled with low standard deviation and variance, points to consistent and predictable intervals. This regularity is a hallmark of beaconing, where a compromised system frequently "checks in" with a C2 server at nearly fixed intervals. Recognizing this pattern is a critical indicator of a beacon, often used by malware for periodic communication with a C2 server. Through effective log parsing, you can detect such malicious activities and enhance your cybersecurity defenses.















  

