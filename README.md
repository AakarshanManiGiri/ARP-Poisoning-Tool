<p align="center">
  <img src="https://capsule-render.vercel.app/api?text=ARP%20Poisoning%20Tool&type=waving&color=gradient&height=120"/>
</p>
<p align="center">
<a href="https://www.codefactor.io/repository/github/aakarshanmanigiri/arp-poisoning-tool/overview/main" align="center"><img src="https://www.codefactor.io/repository/github/aakarshanmanigiri/arp-poisoning-tool/badge/main" alt="CodeFactor"/></a>
</p>
<p align="center">
  <b>ARP Spoofing Tool</b><br>
  A python tool that performs ARP cache poisoning
</p>
<h2>Introduction</h2>
ARP aka Address Resolution Protocol is a process that is responsible for the mapping of MAC Addresses (Hardware Identifier) To IP Addresses (Network Identifier), However ARP has some major shortcomings namely it's
stateless and unauthenticated nature. In an ARP Poisoning/Spoofing attack malicious ARP Packets are sent to a default gateway on LAN with the intent to change the IP address - MAC address pairings in the ARP cache table.
This is done via repeatedly sending falsified ARP replies to the Victim. It is repeatedly done due to the volatile nature of ARP Cache, The ARP cache table on systems has a very short half-life namely 30-60 seconds on Linux
1-2 mins on Windows and 1-20 mins on MACOS. Attackers can leverage ARP cache poisoning to commit MITM Attacks.
<h2>What is a MITM (Man In The Middle) Attack?</h2>
A MITM (Man in The Middle) Attack is a network interception attack via which the attacker intercepts and relays network traffic between 2 entities, This allows the attacker to read, record and even alter traffic.<br>
In this case:<br>
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/3261e366-dce1-4636-a734-f07d65b0dfb0" />
<h2>Detection/Mitigation Methods for ARP Spoofing</h2>
<ul>
    <li>Static ARP Tables</li>
    <li>Dynamic ARP Inspection</li>
    <li>Encrypted Traffic</li>
    <li>Host-Based Firewall Rules</li>
  </ul>





<h2>Disclaimer</h2>
This Project is designed exclusively for educational purposes only.

