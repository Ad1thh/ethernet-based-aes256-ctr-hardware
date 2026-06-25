#include <stdio.h>
#include <string.h>

#include "xparameters.h"
#include "netif/xadapter.h"
#include "platform.h"
#include "platform_config.h"
#include "xil_printf.h"
#include "xil_io.h"
#include "xil_cache.h"
#include "xtime_l.h"
#include "xaxidma.h"

#include "lwip/err.h"
#include "lwip/tcp.h"
#include "lwip/init.h"

// ==============================================================================
// SOFTWARE AES-256 CTR IMPLEMENTATION (Merged into main.c)
// ==============================================================================

// Standard AES S-Box table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t get_sbox(uint8_t val) {
    return sbox[val];
}

// AES Round Constants (Rcon)
static const uint32_t rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// GF(2^8) multiplication by 2
static uint8_t xtime(uint8_t b) {
    return (b & 0x80) ? ((b << 1) ^ 0x1b) : (b << 1);
}

// 32-bit Rotate Word (RotWord)
static uint32_t rot_word(uint32_t temp) {
    return (temp << 8) | (temp >> 24);
}

// 32-bit Substitute Word (SubWord)
static uint32_t sub_word(uint32_t temp) {
    return ((uint32_t)get_sbox((temp >> 24) & 0xFF) << 24) |
           ((uint32_t)get_sbox((temp >> 16) & 0xFF) << 16) |
           ((uint32_t)get_sbox((temp >> 8)  & 0xFF) << 8)  |
            (uint32_t)get_sbox(temp         & 0xFF);
}

// AES-256 Key Expansion
void aes256_sw_init(const uint8_t *key, uint32_t *round_keys) {
    int j;
    uint32_t temp;

    // Load first 8 words directly from the 256-bit key (Big Endian)
    for (j = 0; j < 8; j++) {
        round_keys[j] = ((uint32_t)key[4 * j]     << 24) |
                        ((uint32_t)key[4 * j + 1] << 16) |
                        ((uint32_t)key[4 * j + 2] << 8)  |
                         (uint32_t)key[4 * j + 3];
    }

    // Expand the remaining 52 words
    for (j = 8; j < 60; j++) {
        temp = round_keys[j - 1];
        if (j % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[j / 8];
        } else if (j % 8 == 4) {
            temp = sub_word(temp);
        }
        round_keys[j] = round_keys[j - 8] ^ temp;
    }
}

// Single block (16-byte) AES-256 encryption
void aes256_sw_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, const uint32_t *round_keys) {
    uint8_t state[4][4];
    uint8_t temp[4][4];
    int r, c, round;

    // 1. Copy plaintext to state array (Column-major order)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = plaintext[r + 4 * c];
        }
    }

    // 2. Initial Round (AddRoundKey with Key 0)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] ^= (round_keys[c] >> (24 - 8 * r)) & 0xFF;
        }
    }

    // 3. Rounds 1 to 13
    for (round = 1; round <= 13; round++) {
        // SubBytes
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = get_sbox(state[r][c]);
            }
        }

        // ShiftRows
        // Row 0: no shift
        // Row 1: circular shift left by 1
        uint8_t t1 = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = t1;

        // Row 2: circular shift left by 2
        uint8_t t2_0 = state[2][0];
        uint8_t t2_1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = t2_0;
        state[2][3] = t2_1;

        // Row 3: circular shift left by 3 (shift right by 1)
        uint8_t t3 = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = t3;

        // MixColumns
        for (c = 0; c < 4; c++) {
            uint8_t a = state[0][c];
            uint8_t b = state[1][c];
            uint8_t cv = state[2][c];
            uint8_t d = state[3][c];

            temp[0][c] = xtime(a) ^ (xtime(b) ^ b) ^ cv ^ d;
            temp[1][c] = a ^ xtime(b) ^ (xtime(cv) ^ cv) ^ d;
            temp[2][c] = a ^ b ^ xtime(cv) ^ (xtime(d) ^ d);
            temp[3][c] = (xtime(a) ^ a) ^ b ^ cv ^ xtime(d);
        }
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] = temp[r][c];
            }
        }

        // AddRoundKey
        for (r = 0; r < 4; r++) {
            for (c = 0; c < 4; c++) {
                state[r][c] ^= (round_keys[4 * round + c] >> (24 - 8 * r)) & 0xFF;
            }
        }
    }

    // 4. Round 14 (Final round - no MixColumns)
    // SubBytes
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] = get_sbox(state[r][c]);
        }
    }

    // ShiftRows
    uint8_t t1_final = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = t1_final;

    uint8_t t2_0_final = state[2][0];
    uint8_t t2_1_final = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t2_0_final;
    state[2][3] = t2_1_final;

    uint8_t t3_final = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = t3_final;

    // AddRoundKey with Key 14
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            state[r][c] ^= (round_keys[4 * 14 + c] >> (24 - 8 * r)) & 0xFF;
        }
    }

    // 5. Copy state back to ciphertext (Column-major order)
    for (r = 0; r < 4; r++) {
        for (c = 0; c < 4; c++) {
            ciphertext[r + 4 * c] = state[r][c];
        }
    }
}

// AES-256 CTR encryption/decryption
void aes256_sw_ctr_crypt(const uint8_t *in, uint8_t *out, uint32_t len, const uint8_t *key, const uint8_t *iv) {
    uint32_t round_keys[60];
    uint8_t ctr_block[16];
    uint8_t keystream[16];
    uint32_t offset = 0;
    int i;

    // Initialize key expansion
    aes256_sw_init(key, round_keys);

    // Load initial counter (IV)
    memcpy(ctr_block, iv, 16);

    // Process blocks of 16 bytes
    while (offset + 16 <= len) {
        // Encrypt the counter block
        aes256_sw_encrypt_block(ctr_block, keystream, round_keys);

        // XOR plaintext with keystream
        for (i = 0; i < 16; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        // Increment counter (128-bit big-endian)
        for (i = 15; i >= 0; i--) {
            ctr_block[i]++;
            if (ctr_block[i] != 0) {
                break;
            }
        }

        offset += 16;
    }

    // Process remaining partial block (if any)
    if (offset < len) {
        aes256_sw_encrypt_block(ctr_block, keystream, round_keys);
        for (i = 0; offset + i < len; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
    }
}

// ==============================================================================
// SYSTEM CONFIGURATION AND DMA
// ==============================================================================

// Fallback definitions for Vitis compatibility
#ifndef XPAR_AXIDMA_0_DEVICE_ID
  #ifdef XPAR_XAXIDMA_0_DEVICE_ID
    #define XPAR_AXIDMA_0_DEVICE_ID XPAR_XAXIDMA_0_DEVICE_ID
  #else
    #define XPAR_AXIDMA_0_DEVICE_ID 0
  #endif
#endif

#ifndef AES_BASEADDR
  #ifdef XPAR_AES256_CTR_TOP_0_BASEADDR
    #define AES_BASEADDR XPAR_AES256_CTR_TOP_0_BASEADDR
  #else
    #define AES_BASEADDR 0x43C00000 // Default Zynq GP0 AXI-Lite Slot 0 Base Address
  #endif
#endif

// System Configuration
#define PORT 7
#define MAX_FILE_SIZE (1024 * 1024) // 1 Megabyte max file size
#define HEADER_SIZE 53 // 1 (mode) + 32 (key) + 16 (iv) + 4 (file_size)

// Cache-aligned buffers for DMA transfers
static uint8_t data_in_buf[MAX_FILE_SIZE] __attribute__ ((aligned(32)));
static uint8_t data_out_buf[MAX_FILE_SIZE] __attribute__ ((aligned(32)));

// TCP Session State Variables
typedef enum {
    STATE_WAIT_HEADER,
    STATE_WAIT_DATA,
    STATE_PROCESSING,
    STATE_SENDING_RESP,
    STATE_DONE
} session_state_t;

typedef struct {
    uint8_t mode;
    uint8_t key[32];
    uint8_t iv[16];
    uint32_t file_size;
} aes_header_t;

static session_state_t session_state = STATE_WAIT_HEADER;
static aes_header_t header;
static uint32_t header_received_bytes = 0;
static uint8_t header_buf[HEADER_SIZE];

static uint32_t data_received_bytes = 0;
static uint32_t data_sent_bytes = 0;
static uint32_t elapsed_us = 0;

static XAxiDma AxiDma;
struct netif server_netif;
struct netif *echo_netif;

extern volatile int TcpFastTmrFlag;
extern volatile int TcpSlowTmrFlag;
void tcp_fasttmr(void);
void tcp_slowtmr(void);

// Forward declarations
void print_app_header();
err_t accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err);
err_t recv_callback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
err_t send_callback(void *arg, struct tcp_pcb *tpcb, uint16_t len);

// Initialize AXI DMA Core
int init_aes_dma() {
    XAxiDma_Config *CfgPtr;
    int Status;

    xil_printf("Initializing AXI DMA core...\r\n");
    CfgPtr = XAxiDma_LookupConfig(XPAR_AXIDMA_0_DEVICE_ID);
    if (!CfgPtr) {
        xil_printf("No config found for DMA %d\r\n", XPAR_AXIDMA_0_DEVICE_ID);
        return XST_FAILURE;
    }

    Status = XAxiDma_CfgInitialize(&AxiDma, CfgPtr);
    if (Status != XST_SUCCESS) {
        xil_printf("Initialization failed %d\r\n", Status);
        return Status;
    }

    if (XAxiDma_HasSg(&AxiDma)) {
        xil_printf("Device configured as SG mode, need simple mode\r\n");
        return XST_FAILURE;
    }

    // Disable interrupts, we will poll for transfer completion
    XAxiDma_IntrDisable(&AxiDma, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_IntrDisable(&AxiDma, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DMA_TO_DEVICE);

    xil_printf("AXI DMA core initialized successfully.\r\n");
    return XST_SUCCESS;
}

// Start LwIP TCP Server Listener
int start_application() {
    struct tcp_pcb *pcb;
    err_t err;

    pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) {
        xil_printf("Error creating PCB. Out of Memory\r\n");
        return -1;
    }

    err = tcp_bind(pcb, IP_ANY_TYPE, PORT);
    if (err != ERR_OK) {
        xil_printf("Unable to bind to port %d: err = %d\r\n", PORT, err);
        return -2;
    }

    tcp_arg(pcb, NULL);
    pcb = tcp_listen(pcb);
    if (!pcb) {
        xil_printf("Out of memory while tcp_listen\r\n");
        return -3;
    }

    tcp_accept(pcb, accept_callback);
    xil_printf("AES-256 CTR Server started @ port %d\r\n", PORT);
    return 0;
}

err_t accept_callback(void *arg, struct tcp_pcb *newpcb, err_t err) {
    xil_printf("New connection accepted.\r\n");
    
    // Reset session variables
    session_state = STATE_WAIT_HEADER;
    header_received_bytes = 0;
    data_received_bytes = 0;
    data_sent_bytes = 0;
    elapsed_us = 0;

    tcp_recv(newpcb, recv_callback);
    return ERR_OK;
}

// Write the timing header and ciphertext back to the PC client
void send_response(struct tcp_pcb *tpcb) {
    err_t err;
    uint32_t chunk_len;
    uint32_t remaining_bytes;

    // Send elapsed time header first (4 bytes, Big Endian)
    if (data_sent_bytes == 0) {
        uint8_t time_buf[4];
        time_buf[0] = (elapsed_us >> 24) & 0xFF;
        time_buf[1] = (elapsed_us >> 16) & 0xFF;
        time_buf[2] = (elapsed_us >> 8)  & 0xFF;
        time_buf[3] =  elapsed_us        & 0xFF;

        err = tcp_write(tpcb, time_buf, 4, TCP_WRITE_FLAG_MORE);
        if (err != ERR_OK) {
            xil_printf("Error writing time header: %d\r\n", err);
            return;
        }
    }

    // Determine chunk size based on remaining data and TCP window limits
    remaining_bytes = header.file_size - data_sent_bytes;
    chunk_len = tcp_sndbuf(tpcb);
    if (chunk_len > remaining_bytes) {
        chunk_len = remaining_bytes;
    }

    if (chunk_len > 0) {
        err = tcp_write(tpcb, (void *)(data_out_buf + data_sent_bytes), chunk_len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            data_sent_bytes += chunk_len;
            tcp_output(tpcb); // Push data instantly
        } else {
            xil_printf("tcp_write failed: %d\r\n", err);
        }
    }

    if (data_sent_bytes == header.file_size) {
        xil_printf("Transaction complete. Sent %lu bytes.\r\n", data_sent_bytes);
        session_state = STATE_WAIT_HEADER; // Reset state for next transaction
        header_received_bytes = 0;
        data_received_bytes = 0;
        data_sent_bytes = 0;
    }
}

// Receive callback called when data packets arrive from network
err_t recv_callback(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (!p) {
        xil_printf("Connection closed by client.\r\n");
        tcp_close(tpcb);
        return ERR_OK;
    }

    tcp_recved(tpcb, p->len);
    
    uint32_t payload_offset = 0;
    uint32_t payload_len = p->len;
    uint8_t *payload_ptr = (uint8_t *)p->payload;

    while (payload_offset < payload_len) {
        if (session_state == STATE_WAIT_HEADER) {
            // Read header bytes
            uint32_t bytes_to_copy = HEADER_SIZE - header_received_bytes;
            if (bytes_to_copy > (payload_len - payload_offset)) {
                bytes_to_copy = payload_len - payload_offset;
            }

            memcpy(header_buf + header_received_bytes, payload_ptr + payload_offset, bytes_to_copy);
            header_received_bytes += bytes_to_copy;
            payload_offset += bytes_to_copy;

            if (header_received_bytes == HEADER_SIZE) {
                // Parse Header
                header.mode = header_buf[0];
                memcpy(header.key, header_buf + 1, 32);
                memcpy(header.iv, header_buf + 33, 16);
                header.file_size = ((uint32_t)header_buf[49] << 24) |
                                   ((uint32_t)header_buf[50] << 16) |
                                   ((uint32_t)header_buf[51] << 8)  |
                                    (uint32_t)header_buf[52];

                xil_printf("\r\n[PS] Parsed Header - Mode: %d, Size: %lu bytes\r\n", header.mode, header.file_size);
                
                if (header.file_size > MAX_FILE_SIZE) {
                    xil_printf("[PS] ERROR: File exceeds max supported size (%d MB)\r\n", MAX_FILE_SIZE / (1024*1024));
                    tcp_close(tpcb);
                    pbuf_free(p);
                    return ERR_VAL;
                }

                session_state = STATE_WAIT_DATA;
                data_received_bytes = 0;
            }
        }
        else if (session_state == STATE_WAIT_DATA) {
            // Read file payload
            uint32_t bytes_to_copy = header.file_size - data_received_bytes;
            if (bytes_to_copy > (payload_len - payload_offset)) {
                bytes_to_copy = payload_len - payload_offset;
            }

            memcpy(data_in_buf + data_received_bytes, payload_ptr + payload_offset, bytes_to_copy);
            data_received_bytes += bytes_to_copy;
            payload_offset += bytes_to_copy;

            if (data_received_bytes == header.file_size) {
                session_state = STATE_PROCESSING;
                xil_printf("[PS] All file data received (%lu bytes). Running encryption...\r\n", data_received_bytes);

                XTime tStart, tEnd;

                if (header.mode == 0 || header.mode == 1) {
                    // ==========================================
                    // RUN SOFTWARE BENCHMARK
                    // ==========================================
                    xil_printf("  Executing Software AES-256 CTR...\r\n");
                    XTime_GetTime(&tStart);
                    aes256_sw_ctr_crypt(data_in_buf, data_out_buf, header.file_size, header.key, header.iv);
                    XTime_GetTime(&tEnd);
                    
                    elapsed_us = (uint32_t)((double)(tEnd - tStart) / (COUNTS_PER_SECOND / 1000000.0));
                    xil_printf("  Software Complete. Time: %lu us\r\n", elapsed_us);
                } 
                else if (header.mode == 2 || header.mode == 3) {
                    // ==========================================
                    // RUN HARDWARE ACCELERATOR
                    // ==========================================
                    xil_printf("  Executing Hardware AES-256 CTR (AXI DMA)...\r\n");

                    // 1. Program Custom PL IP registers via AXI-Lite
                    // Key registers (REG 0 to 7)
                    int i;
                    for (i = 0; i < 8; i++) {
                        uint32_t word = ((uint32_t)header.key[4*i]   << 24) |
                                        ((uint32_t)header.key[4*i+1] << 16) |
                                        ((uint32_t)header.key[4*i+2] << 8)  |
                                         (uint32_t)header.key[4*i+3];
                        Xil_Out32(AES_BASEADDR + 4*i, word);
                    }
                    // IV registers (REG 8 to 11)
                    for (i = 0; i < 4; i++) {
                        uint32_t word = ((uint32_t)header.iv[4*i]   << 24) |
                                        ((uint32_t)header.iv[4*i+1] << 16) |
                                        ((uint32_t)header.iv[4*i+2] << 8)  |
                                         (uint32_t)header.iv[4*i+3];
                        Xil_Out32(AES_BASEADDR + 0x20 + 4*i, word);
                    }
                    
                    // Pulse Start Strobe (REG 12 bit 0) to load parameters
                    Xil_Out32(AES_BASEADDR + 0x30, 0x00000001);

                    // 2. Cache Operations for DMA Coherency
                    // Flush TX buffer: ensures DDR holds the latest data from the CPU
                    Xil_DCacheFlushRange((UINTPTR)data_in_buf, header.file_size);
                    // Invalidate RX buffer: clears stale cache so CPU reads new data from DMA
                    Xil_DCacheInvalidateRange((UINTPTR)data_out_buf, header.file_size);

                    // 3. Start DMA Transfers and Measure Time
                    XTime_GetTime(&tStart);

                    // DMA from DDR to PL IP (Transmit)
                    int Status = XAxiDma_SimpleTransfer(&AxiDma, (UINTPTR)data_in_buf, header.file_size, XAXIDMA_DMA_TO_DEVICE);
                    if (Status != XST_SUCCESS) {
                        xil_printf("  ERROR: DMA Tx transfer failed: %d\r\n", Status);
                    }

                    // DMA from PL IP to DDR (Receive)
                    Status = XAxiDma_SimpleTransfer(&AxiDma, (UINTPTR)data_out_buf, header.file_size, XAXIDMA_DEVICE_TO_DMA);
                    if (Status != XST_SUCCESS) {
                        xil_printf("  ERROR: DMA Rx transfer failed: %d\r\n", Status);
                    }

                    // Poll for DMA completion
                    while (XAxiDma_Busy(&AxiDma, XAXIDMA_DMA_TO_DEVICE)) ;
                    while (XAxiDma_Busy(&AxiDma, XAXIDMA_DEVICE_TO_DMA)) ;

                    XTime_GetTime(&tEnd);
                    
                    elapsed_us = (uint32_t)((double)(tEnd - tStart) / (COUNTS_PER_SECOND / 1000000.0));
                    xil_printf("  Hardware Complete. Time: %lu us\r\n", elapsed_us);
                }

                session_state = STATE_SENDING_RESP;
                data_sent_bytes = 0;
                
                // Set send callback to continue writing chunks as buffer space clears
                tcp_sent(tpcb, send_callback);
                send_response(tpcb);
            }
        }
    }

    pbuf_free(p);
    return ERR_OK;
}

// Sent callback triggered when downstream network ACKs bytes and frees send buffer space
err_t send_callback(void *arg, struct tcp_pcb *tpcb, uint16_t len) {
    if (session_state == STATE_SENDING_RESP) {
        send_response(tpcb);
    }
    return ERR_OK;
}

void print_app_header() {
    xil_printf("\r\n====================================================\r\n");
    xil_printf(" Zynq-7000 Hardware AES-256 CTR Ethernet Gateway    \r\n");
    xil_printf(" Department of Electronics, CUSAT Internship        \r\n");
    xil_printf("====================================================\r\n");
    xil_printf("Static IP Address   : 192.168.1.10\r\n");
    xil_printf("Listening TCP Port  : %d\r\n", PORT);
    xil_printf("DMA Configuration   : Polled mode, Big Endian counters\r\n");
    xil_printf("====================================================\r\n\r\n");
}

int main() {
    ip_addr_t ipaddr, netmask, gw;
    
    // Board MAC Address (must be unique)
    unsigned char mac_ethernet_address[] = { 0x00, 0x0a, 0x35, 0x00, 0x01, 0x02 };

    echo_netif = &server_netif;

    // Platform SCU Timer and GIC initialization
    init_platform();

    // Configure static IP network settings
    IP4_ADDR(&ipaddr,  192, 168,   1, 10);
    IP4_ADDR(&netmask, 255, 255, 255,  0);
    IP4_ADDR(&gw,      192, 168,   1,  1);

    print_app_header();

    // Initialize AXI DMA Core
    if (init_aes_dma() != XST_SUCCESS) {
        xil_printf("ERROR: AXI DMA initialization failed!\r\n");
        return -1;
    }

    // Initialize LwIP stack
    lwip_init();

    // Add network adapter interface
    if (!xemac_add(echo_netif, &ipaddr, &netmask, &gw, mac_ethernet_address, PLATFORM_EMAC_BASEADDR)) {
        xil_printf("Error adding N/W interface\r\n");
        return -1;
    }
    netif_set_default(echo_netif);

    // Enable CPU Interrupts (for LwIP SCU Timer ticks, DMA is polled)
    platform_enable_interrupts();
    netif_set_up(echo_netif);

    xil_printf("Network Settings:\r\n");
    xil_printf("  Board IP: %d.%d.%d.%d\r\n", ip4_addr1(&ipaddr), ip4_addr2(&ipaddr), ip4_addr3(&ipaddr), ip4_addr4(&ipaddr));
    xil_printf("  Netmask : %d.%d.%d.%d\r\n", ip4_addr1(&netmask), ip4_addr2(&netmask), ip4_addr3(&netmask), ip4_addr4(&netmask));
    xil_printf("  Gateway : %d.%d.%d.%d\r\n", ip4_addr1(&gw), ip4_addr2(&gw), ip4_addr3(&gw), ip4_addr4(&gw));

    // Start TCP Listener
    start_application();

    // Main infinite loop processing timers and packets
    while (1) {
        if (TcpFastTmrFlag) {
            tcp_fasttmr();
            TcpFastTmrFlag = 0;
        }
        if (TcpSlowTmrFlag) {
            tcp_slowtmr();
            TcpSlowTmrFlag = 0;
        }
        xemacif_input(echo_netif); // Poll network packets
    }

    // Unreachable
    cleanup_platform();
    return 0;
}
