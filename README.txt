
Client using UDP protocol for sending IEEE 802.11-style frames to an Access Point (AP)

Description:
This project simulates wireless communication between a client (Station) and an Access
Point using UDP sockets. The client builds and sends IEEE 802.11-like frames; the server
acts as the AP, validates each frame's FCS (Frame Check Sequence), and responds with the
appropriate management, control, or data reply.

Files:
  client.c  - Client (Station) that sends frames to the AP
  server.c  - Access Point that receives frames and sends responses

Supported frame exchange:
  - Association Request  -> Association Response
  - Probe Request        -> Probe Response
  - RTS (Request to Send)-> CTS (Clear to Send)
  - Data frames          -> ACK
  - Fragmented data frames (5 fragments) with reassembly on the AP
  - FCS error detection and retry (up to 3 attempts per frame)

Pre-requisite:
  Install gcc on Linux for C program compilation

How to compile and run in Linux:

1. Copy client.c and server.c to the desired location.
2. Compile both programs:
     gcc server.c -o server
     gcc client.c -o client
3. Start the Access Point (server) first:
     ./server
4. In a new terminal, run the client:
     ./client
5. Frame transmission output will appear in both terminal windows.

Notes:
  - The server listens on UDP port 5000 (127.0.0.1).
  - The client sends a sequence of management, control, and data frames, including
    fragmented data and intentionally corrupted frames to demonstrate FCS checking
    and retry behavior.
