// client.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>

#define SERVER_PORT 5000
#define MAX_RETRIES 3
#define MAX_PAYLOAD 2312
#define START_OF_FRAME_ID 0xFFFF
#define END_OF_FRAME_ID   0xFFFF

typedef struct {
    uint16_t protocol_version : 2;
    uint16_t type             : 2;
    uint16_t subtype          : 4;
    uint16_t to_ds            : 1;
    uint16_t from_ds          : 1;
    uint16_t more_fragments   : 1;
    uint16_t retry            : 1;
    uint16_t power_mgmt       : 1;
    uint16_t more_data        : 1;
    uint16_t wep              : 1;
    uint16_t order            : 1;
} __attribute__((packed)) FrameControl;

typedef struct {
    uint16_t start_of_frame;
    FrameControl fc;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t addr4[6];
    uint16_t sequence_control;
    uint8_t payload[MAX_PAYLOAD];
    uint32_t fcs;
    uint16_t end_of_frame;
} __attribute__((packed)) IEEEFrame;

uint32_t generate32bitChecksum(const char* valueToConvert) {
    uint32_t checksum = 0;
    while (*valueToConvert) {
        checksum += *valueToConvert++;
        checksum += (checksum << 10);
        checksum ^= (checksum >> 6);
    }
    checksum += (checksum << 3);
    checksum ^= (checksum >> 11);
    checksum += (checksum << 15);
    return checksum;
}

uint32_t getCheckSumValue(const void *ptr, size_t size, ssize_t skipStart, size_t skipEnd) {
    const unsigned char *byte = (const unsigned char *)ptr;
    char binaryString[9]; binaryString[8] = '\0';
    char *buffer = malloc(1); buffer[0] = '\0';

    for (size_t i = 1; i <= size; i++) {
        for (int j = 7; j >= 0; j--) {
            binaryString[7 - j] = ((byte[i - 1] >> j) & 1) + '0';
        }
        buffer = realloc(buffer, strlen(buffer) + 9);
        strcat(buffer, binaryString);
    }
    buffer[strlen(buffer)-(skipEnd*8)] = '\0';
    memmove(buffer, buffer + (skipStart*8), strlen(buffer) - (skipStart*8) + 1);
    uint32_t checkSumValue = generate32bitChecksum(buffer);
    free(buffer);
    return checkSumValue;
}

void generate_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++)
        mac[i] = rand() % 256;
}

void prepare_frame(IEEEFrame *frame, uint8_t type, uint8_t subtype, uint16_t duration_id, const char *message, uint8_t *addr1, uint8_t *addr2, uint8_t *addr3,uint8_t more_fragments_flag) {
    memset(frame, 0, sizeof(IEEEFrame));
    frame->start_of_frame = START_OF_FRAME_ID;
    frame->fc.protocol_version = 0;
    frame->fc.type = type;
    frame->fc.subtype = subtype;
// Client to AP: ToDS = 1, FromDS = 0 for Data frames (infrastructure mode)
if (type == 2) {  // Data frame
    frame->fc.to_ds = 1;
    frame->fc.from_ds = 0;
} else {
    frame->fc.to_ds = 0;
    frame->fc.from_ds = 0;
}

frame->fc.more_fragments = more_fragments_flag;
frame->fc.retry = 0;
frame->fc.power_mgmt = 0;
frame->fc.more_data = 0;
frame->fc.wep = 0;
frame->fc.order = 0;

    frame->duration_id = duration_id;
    memcpy(frame->addr1, addr1, 6);
    memcpy(frame->addr2, addr2, 6);
    memcpy(frame->addr3, addr3, 6);
    memset(frame->addr4, 0, 6);
    frame->sequence_control = rand() % 65536;
    if (message)
        strncpy((char*)frame->payload, message, MAX_PAYLOAD);
    frame->fcs = getCheckSumValue(frame, sizeof(IEEEFrame), 2, 6);
    frame->end_of_frame = END_OF_FRAME_ID;
}
void print_frame(const IEEEFrame* frame) {
    //printf("---- Received IEEE 802.11 Frame ----\n");
    printf("Start of Frame: 0x%04X\n", frame->start_of_frame);
     printf("Payload: ");
    for (int i = 0; i < MAX_PAYLOAD; i++) {
        if (frame->payload[i] == '\0') break;
        printf("%c", frame->payload[i]);
    }
    printf("\n");

    printf("Frame Control:\n");
    printf("  Protocol Version: %u\n", frame->fc.protocol_version);
    printf("  Type: %u\n", frame->fc.type);
    printf("  Subtype: 0x%02X\n", frame->fc.subtype);
    printf("  To DS: %u\n", frame->fc.to_ds);
    printf("  From DS: %u\n", frame->fc.from_ds);
    printf("  More Fragments: %u\n", frame->fc.more_fragments);
    printf("  Retry: %u\n", frame->fc.retry);
    printf("  Power Management: %u\n", frame->fc.power_mgmt);
    printf("  More Data: %u\n", frame->fc.more_data);
    printf("  WEP: %u\n", frame->fc.wep);
    printf("  Order: %u\n", frame->fc.order);

    printf("Duration ID: %u\n", frame->duration_id);

    printf("Address 1: %02X:%02X:%02X:%02X:%02X:%02X\n",
           frame->addr1[0], frame->addr1[1], frame->addr1[2],
           frame->addr1[3], frame->addr1[4], frame->addr1[5]);
    printf("Address 2: %02X:%02X:%02X:%02X:%02X:%02X\n",
           frame->addr2[0], frame->addr2[1], frame->addr2[2],
           frame->addr2[3], frame->addr2[4], frame->addr2[5]);
    printf("Address 3: %02X:%02X:%02X:%02X:%02X:%02X\n",
           frame->addr3[0], frame->addr3[1], frame->addr3[2],
           frame->addr3[3], frame->addr3[4], frame->addr3[5]);
    printf("Address 4: %02X:%02X:%02X:%02X:%02X:%02X\n",
           frame->addr4[0], frame->addr4[1], frame->addr4[2],
           frame->addr4[3], frame->addr4[4], frame->addr4[5]);

    printf("Sequence Control: %u\n", frame->sequence_control);

   

    printf("FCS: 0x%08X\n", frame->fcs);
    printf("End of Frame: 0x%04X\n", frame->end_of_frame);
    printf("-----------------------------------\n");
}


int send_and_receive(int sock, struct sockaddr_in *server, IEEEFrame *frame, const char *label,int corrupt) {
    socklen_t slen = sizeof(*server);
    IEEEFrame buffer = {0};
    int retries = 0;

    struct timeval timeout = {3, 0}; // 3 seconds timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (retries < MAX_RETRIES) {
        if(retries>0)
        {
            frame->fc.retry=1;
            if(corrupt!=1)
            {

                frame->fcs = getCheckSumValue(frame, sizeof(IEEEFrame), 2, 6);
            }
            

        }
        printf("Sending %s frame (attempt %d)...\n", label, retries + 1);
        print_frame(frame);
        sendto(sock, frame, sizeof(*frame), 0, (struct sockaddr *)server, slen);

        int resp = recvfrom(sock, &buffer, sizeof(buffer), 0, NULL, NULL);
        if (resp > 0) {
            printf("Received response for %s:\n", label);
            print_frame(&buffer);
            int flag=0;
            
            // Check if received frame is an ACK (type=1, subtype=13 or 0x0D)
            if (buffer.fc.type == 1 && buffer.fc.subtype == 0x0D) {
                printf("ACK received for %s.\n\n", label);
                
            } else if (buffer.fc.type == 1 && buffer.fc.subtype == 0x0C) {
                printf("CTS received for %s.\n\n", label);
                
            }else if (buffer.fc.type == 0 && buffer.fc.subtype == 0x01) {
                printf("Association Response received for %s.\n\n", label);
                
            }else if (buffer.fc.type == 0 && buffer.fc.subtype == 0x05) {
                printf("Probe Response received for %s.\n\n", label);
                
            }
            else {
                flag=1;
                printf("Received non-matching frame. Retrying...\n");
            }

            if(flag==0){
                return buffer.duration_id;
            }



        } else {
            printf("No ACK recvied for %s. Retrying...\n", label);
        }

        retries++;
    }

    printf("Failed to receive ACK for %s after %d attempts.\n\n", label, MAX_RETRIES);
    printf("No ACK received from AP\n\n");
    return -1;
}


int main() {
    srand(time(NULL));
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };

    uint8_t client_mac[6], ap_mac[6];
    generate_mac(client_mac);
    generate_mac(ap_mac);

    IEEEFrame frame;
int corrupt=0;
    prepare_frame(&frame, 0, 0x00, 0, "Association Request", ap_mac, client_mac, ap_mac,0);
    send_and_receive(sock, &server, &frame, "Association Request",corrupt);

    prepare_frame(&frame, 0, 0x04, 0, "Probe Request", ap_mac, client_mac, ap_mac,0);
    send_and_receive(sock, &server, &frame, "Probe Request",corrupt);

    prepare_frame(&frame, 1, 0x0B, 4, "RTS", ap_mac, client_mac, ap_mac,0);
    send_and_receive(sock, &server, &frame, "RTS",corrupt);

    prepare_frame(&frame, 2, 0x00, 2, "Data Frame", ap_mac, client_mac, ap_mac,0);
    send_and_receive(sock, &server, &frame, "Data Frame",corrupt);

//     // Send a corrupted frame to test FCS error handling
// prepare_frame(&frame, 2, 0x00, 2, "Corrupted Frame", ap_mac, client_mac, ap_mac);

// // Corrupt the FCS intentionally
// frame.fcs = 0xDEADBEEF;

// send_and_receive(sock, &server, &frame, "Corrupted Frame");


int remaining_duration = 12;
    // RTS
    prepare_frame(&frame, 1, 0x0B, 12, "RTS", ap_mac, client_mac, ap_mac,0);
    remaining_duration=send_and_receive(sock, &server, &frame, "RTS",corrupt);

    // CTS will be received inside send_and_receive and printed

    // Send 5 fragmented data frames
    
    for (int i = 0; i < 5; i++) {
        
        int more_frag = (i < 4); // 1 if more fragments follow, 0 for last fragment
        char payload[32];
        snprintf(payload, sizeof(payload), "Data Frag %d", i + 1); 
        int current_duration = remaining_duration - 1;
        remaining_duration = current_duration;
        prepare_frame(&frame, 2, 0x00, current_duration, payload, ap_mac, client_mac, ap_mac,more_frag);
   
        char label[32];
        snprintf(label, sizeof(label), "Data Frag %d", i + 1);
        remaining_duration =send_and_receive(sock, &server, &frame, label,corrupt);
    }



   




for (int i = 0; i < 5; i++) {
    int more_frag = (i < 4); // 1 if more fragments follow, 0 for last fragment
    char payload[32];
    snprintf(payload, sizeof(payload), "Data Frag %d", i + 1); 

    int attempts = 0;
    
    // int ack_received = 0;

    // while (attempts < retry_ack_counter && !ack_received) {
    //     int current_duration = remaining_duration - 1;
    //     remaining_duration = current_duration;

       
        prepare_frame(&frame, 2, 0x00, 4, payload, ap_mac, client_mac, ap_mac, more_frag);
        char label[64];
        snprintf(label, sizeof(label), "Data Frag %d", i + 1);
         // Introduce error for frames 2-5 (index 1 to 4)
        if (i > 0 && attempts == 0) {
            frame.fcs= 0xffff;  // corrupt the payload intentionally (simulate error)
            corrupt=1;
        }


        // Send and wait for ACK
        int resp = send_and_receive(sock, &server, &frame, label,corrupt);
        // attempts++;
        // printf("ateemtpss %d\n", attempts);


        // if (resp == -1) {
        //     printf("No ACK Received for Frame No. %d (Attempt %d)\n", i + 1, attempts + 1);
        //     attempts++;
        //     if (attempts == retry_ack_counter) {
        //         printf("Frame No. %d dropped after 3 unsuccessful attempts.\n", i + 1);
        //     } else {
        //         sleep(3); // 3-second retry timer
        //     }
        // } else {
        //     ack_received = 1;
        //     remaining_duration = resp; // update remaining duration
        // }
    }





    close(sock);
    return 0;
}
