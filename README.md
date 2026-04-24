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

## Project Videos
- [Deauth Demo on Flipper](https://www.youtube.com/watch?v=_ZSqvmoLcEY)
- [Evil Twin Demo](https://youtu.be/gxdjEiMLCFM)


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

We focused on WPA2 and the assumption that our "victim" would be utilizing a weak or known test password such as one found in rockyou.txt. This made the handshake and dictionary-attack workflow easier to demonstrate. This trade-off reduced realism for stronger modern networks, but it made the security lesson clearer: weak passphrases can fail quickly once an attacker captures the right traffic.

We had to use some of our tools in conjunction to acomplish discovery, capture, cracking, and evil twin broadcast. With different steps being on differing devices it did seperate the project making it easier to test and explain, although it required more setup and coordination than a single automated tool. We were able in the last few weeks of this project automate the cracking and the evil twin broadcasting using our script eviltwin.py.

Our main project goal was to achieve the evil twin but out of the curiosity of learning we did experiment with an evil captive portal. The workflow would be to deauth the say hotel or guest network while at the same time use the Flipper or MiniPC to broadcast the evil network with the same name. A non technical user would then fall for our identical portal and give over information which we could then use against them. 

## Challenges Encountered and Lessons Learned
One major challenge was working on finding a device with the proper network card to achieve our goals of this project. Not every Wi-Fi card supports monitor and AP mode, and the tools behaved differently depending on the operating system, drivers, and chipset. We ended up using a Mini PC found off amazon specifically the Kamrui Pinova P1.

We also found the Flipper Zero deauth was not initially working on our experiment. Narrowing down the variables we realized our ESP32 chip was not strong enough on the 5Ghz band. For the sake of learning we found a router that allowed for the broadcast of a 2.4Ghz Wi-Fi network. The Flipper Zero + ESP32 paired with Marauder firmware was able to successfully deauth a 2.4Ghz network. 

Another challenge was reliably capturing useful handshake traffic. The network interface had to be on the correct channel, and the target client needed to reconnect at the right time for the capture to contain the necessary EAPOL messages. We found that initial attempts using the Flipper Zero were only capturing one or two frames of the four way handshake. Utilizing the Mini PC we found success as we were able to capture all of the frames needed to be able to run a dictionary attack.

Overall, the project reinforced the importance of strong Wi-Fi passwords, modern wireless protections like WPA3, user awareness, and to ensure ethical standards are in practice when conducting experiments of this manner.
