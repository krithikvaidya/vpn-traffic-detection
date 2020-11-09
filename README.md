# VPN-Traffic-Detection

A simple script to detect incoming/outgoing traffic from five well-known VPN services (Hotspot Shield, Hoxx, Browsersec, TOR, Zenmate), and classify packets as suspicious/not suspicious based on predefined rules obtained by inspecting their behaviours.

## Running the Script

Clone the repository
```
git clone https://github.com/krithikvaidya/vpn-traffic-detection.git
```

Change directory
```
cd vpn-traffic-detection
```

Install requirements (Python3 and pip needs to be installed for this)
```
pip install -r requirements.txt
```

Run the script
```
python live_traffic_capture.py
```


#### [Project Report](https://drive.google.com/file/d/1tsrH8vz7eORZ2Q5z0tQ8HLWQgYaIZpMw/view?usp=sharing)
#### [Base Paper](https://dl.acm.org/doi/abs/10.1155/2019/7924690)
