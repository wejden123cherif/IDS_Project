# Python Intrusion Detection System (IDS)

This project is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic and detect common Layer 2 and Layer 4 attacks in real time. It combines packet sniffing with behavioral detection logic and provides a live dashboard for alert visualization.

## Project Objectives
- Monitor network traffic using packet sniffing
- Detect malicious behaviors such as flooding and spoofing attacks
- Generate structured security alerts
- Visualize alerts through a web interface

## Detected Attacks
- **ARP Spoofing**: Detects IP-to-MAC address changes indicating possible man-in-the-middle attacks
- **ARP Flooding**: Detects excessive ARP packets from a single source within a short time window
- **TCP SYN Flooding**: Detects abnormal rates of TCP SYN packets that may indicate denial-of-service attempts

## Architecture
- **Sniffing Layer**: Captures packets using Scapy
- **Detection Layer**: Applies threshold-based logic for each attack type
- **Alert Model**: Stores alerts as structured security events
- **Web Layer**: Flask application displaying alerts in real time
- **Storage**: SQLite database for persistence

## Technologies Used
- Python
- Scapy
- Flask
- SQLite
- attack simulation

## Usage
- Run the IDS on a monitoring machine with network access
- Launch attack simulations in a controlled lab environment
- View detected alerts through the Flask dashboard

## Security Note
This project is intended for **educational purposes only**.  
All attack simulations must be performed in an isolated and authorized lab environment.
