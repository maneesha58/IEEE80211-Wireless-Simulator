// server.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>

#define SERVER_PORT 5000
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

void print_mac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++)
        printf("%02X%s", mac[i], i < 5 ? ":" : "");
}


void print_frame(const IEEEFrame* frame) {
   
    // printf("Start of Frame: 0x%04X\n", frame->start_of_frame);
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
    printf("  Wep: %u\n", frame->fc.wep);
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

void prepare_response(IEEEFrame *resp, const IEEEFrame *req, uint8_t subtype, uint16_t duration_id, const char *payload) {
    memset(resp, 0, sizeof(IEEEFrame));
    resp->start_of_frame = START_OF_FRAME_ID;
    resp->fc.protocol_version = 0;
    resp->fc.type = subtype < 0x0B ? 0 : 1;
    resp->fc.subtype = subtype;
    resp->duration_id = duration_id;

   if (resp->fc.type == 2) {  // Only apply DS bits for Data resps
    // For AP → Client
    resp->fc.to_ds = 0;
    resp->fc.from_ds = 1;
    } else {
        // DS bits are irrelevant for Management and Control frames
        resp->fc.to_ds = 0;
        resp->fc.from_ds = 0;
    }
    resp->fc.more_fragments = 0;
    resp->fc.retry = 0;
    resp->fc.power_mgmt = 0;
    resp->fc.more_data = 0;
    resp->fc.wep = 0;
    resp->fc.order = 0;

    memcpy(resp->addr1, req->addr2, 6);
    memcpy(resp->addr2, req->addr1, 6);
    memcpy(resp->addr3, req->addr3, 6);
    memset(resp->addr4, 0, 6);
    resp->sequence_control = rand() % 65536;
    if (payload)
        strncpy((char*)resp->payload, payload, MAX_PAYLOAD);
    resp->fcs = getCheckSumValue(resp, sizeof(IEEEFrame), 2, 6);
    resp->end_of_frame = END_OF_FRAME_ID;
}

int main() {
    srand(time(NULL));
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(sock, (struct sockaddr*)&server, sizeof(server));
    printf("Access Point listening on port %d...\n", SERVER_PORT);

    struct sockaddr_in client;
    socklen_t clen = sizeof(client);

    while (1) {
        IEEEFrame frame = {0}, response = {0};
        int bytes = recvfrom(sock, &frame, sizeof(frame), 0, (struct sockaddr*)&client, &clen);
        if (bytes <= 0) continue;
        printf("Recived----------------\n");

        print_frame(&frame);
        
        int duration=frame.duration_id;
        duration=duration-1;
        uint32_t calc_fcs = getCheckSumValue(&frame, sizeof(frame), 2, 6);
        printf("Calculated FCS: 0x%08X, Received FCS: 0x%08X\n", calc_fcs, frame.fcs);
         printf("-----------------------------------\n\n");


        if (calc_fcs != frame.fcs) {
            printf("FCS (Frame Check Sequence) Error! Ignoring frame.\n\n");
            printf("-----------------------------------\n\n");
            continue;
        }
       
      switch (frame.fc.type) {
        case 0: // Management frames
            switch (frame.fc.subtype) {
                case 0x00: // Assoc Req
                    prepare_response(&response, &frame, 0x01, 0xCAFE, "Assoc Response");
                    printf("Sending Association Response...\n");
                    print_frame(&response);
                    
                    sendto(sock, &response, sizeof(response), 0, (struct sockaddr*)&client, clen);
                    break;
                case 0x04: // Probe Req
                    prepare_response(&response, &frame, 0x05, 0xBEEF, "Probe Response");
                    printf("Sending Probe response\n\n");
                   
                    print_frame(&response);
                   
                    sendto(sock, &response, sizeof(response), 0, (struct sockaddr*)&client, clen);
                    break;
                // ... other mgmt frames
            }
            break;

        case 1: // Control frames
            switch (frame.fc.subtype) {
                case 0x0B: // RTS
                    prepare_response(&response, &frame, 0x0C, duration, "CTS Response");
                    printf("Sending  CTS response \n\n");
                    
                    print_frame(&response);
                  
                    sendto(sock, &response, sizeof(response), 0, (struct sockaddr*)&client, clen);
                    break;
            }
            break;

      case 2: // Data frames
        {
        static char fragment_buffer[MAX_PAYLOAD * 10]; // Buffer for reassembled fragments
        static int fragment_offset = 0;
      

        switch (frame.fc.subtype) {
            case 0x00: // Data (possibly fragmented)
            { 
                
                int payload_len = strnlen((char*)frame.payload, MAX_PAYLOAD);
                if (fragment_offset + payload_len < sizeof(fragment_buffer)) {
                    memcpy(fragment_buffer + fragment_offset, frame.payload, payload_len);
                    fragment_offset += payload_len;
                } else {
                    printf("Fragment buffer overflow! Resetting buffer.\n");
                    fragment_offset = 0; // Reset on overflow
                    break;
                }

                printf("Received data fragment (more_fragments=%d), total reassembled length=%d\n",
                    frame.fc.more_fragments, fragment_offset);

                // Send ACK for the fragment
                prepare_response(&response, &frame, 0x0D, duration, "ACK");
                print_frame(&response);
               
                sendto(sock, &response, sizeof(response), 0, (struct sockaddr*)&client, clen);

                if (frame.fc.more_fragments == 0) {
                    // Last fragment received, process full data
                    fragment_buffer[fragment_offset] = '\0'; // Null terminate
                    printf("Full data reassembled: %s\n", fragment_buffer);
                    fragment_offset = 0; // Reset for next fragmented message
                }
                break;
            }
            default:
                // Handle other data subtypes if necessary
                break;
        }
    }
    break;


        default:
            sendto(sock, "Unknown type", 13, 0, (struct sockaddr*)&client, clen);
            break;
        }
    }

    close(sock);
    return 0;
}

