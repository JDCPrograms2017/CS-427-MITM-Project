# CPTS-427-MITM-Project

## Class
CPTS 427 Cybersecurity, Spring 2026, Washington State University

## The team
- Joshua Chadwick
- Zachary Felcyn
- Asa Fischer

## Project Documents
- [Project Proposal](docs/project_proposal.md)
- [Technical Notes](docs/technical_notes.md)

## Project Overview and Goals
This project demonstrates wireless man-in-the-middle concepts in a controlled lab environment. The main goal is to understand how wireless clients can be disrupted, redirected, and observed when common Wi-Fi security weaknesses are present.

Our goals include:
- Demonstrate a de-authentication attack against a lab device.
- Explore Evil Twin access point behavior and how clients can be tricked into reconnecting.
- Capture and analyze WPA2 4-way handshake traffic.
- Test password-cracking risk when weak or common passphrases are used.
- Use a captive portal as an educational example of credential-harvesting risk.
- Keep all testing limited to equipment and networks we control.

## Themes Used
- **Wireless protocol security:** We studied how Wi-Fi clients, access points, authentication, and reassociation behave during normal and disrupted network activity.
- **Man-in-the-middle attacks:** The project focuses on how an attacker can position a rogue access point between a client and the expected network path.
- **WPA2 handshake analysis:** We captured handshake traffic and reviewed how weak pre-shared keys can be vulnerable to dictionary attacks.
- **Social engineering and captive portals:** We explored how a fake login flow can exploit user trust even when the technical network setup appears familiar.
- **Ethical security testing:** The work was designed around isolated lab networks, owned hardware, and educational demonstration rather than real-world exploitation.

## Design Decisions and Trade-Offs
We chose a lab-based setup so the project could safely demonstrate realistic wireless attack concepts without affecting outside networks. This made the work more controlled and ethical, but it also meant the results depended on our own hardware, adapter support, and test access point configuration.

We focused on WPA2 and intentionally weak or known test passwords because they make the handshake and dictionary-attack workflow easier to demonstrate. This trade-off reduced realism for stronger modern networks, but it made the security lesson clearer: weak passphrases can fail quickly once an attacker captures the right traffic.

We also separated discovery, capture, cracking, and captive portal work into smaller steps. This made the project easier to test and explain, although it required more setup and coordination than a single automated tool.

## Challenges Encountered and Lessons Learned
One major challenge was working with wireless adapter support. Not every Wi-Fi card supports monitor mode, and the tools behaved differently depending on the operating system, drivers, and chipset.

Another challenge was reliably capturing useful handshake traffic. The network interface had to be on the correct channel, and the target client needed to reconnect at the right time for the capture to contain the necessary EAPOL messages.

We also learned that the most effective security demonstrations are not always the most complex ones. A controlled setup with a weak password, clear packet capture, and careful analysis made the risks easier to understand than trying to simulate every part of a real attack chain.

Overall, the project reinforced the importance of strong Wi-Fi passwords, modern wireless protections, user awareness around captive portals, and strict ethical boundaries when practicing cybersecurity techniques.
