`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_key_expansion
// Description:
//   Sequential Key Expansion for AES-256.
//   Expands 256-bit key into 15 round keys (1920 bits total) over 13 clock cycles.
//   Timing-optimized: registers round keys at each step and shares 4 S-Boxes.
//////////////////////////////////////////////////////////////////////////////////

module aes256_key_expansion (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,      // Pulse high to start key expansion
    input  wire [255:0] key,        // 256-bit input key
    output wire [1919:0] round_keys,
    output reg          ready       // High when round keys are valid
);

    // Round Constant (Rcon) function
    function [7:0] get_rcon;
        input [3:0] idx;
        begin
            case (idx)
                4'd1: get_rcon = 8'h01;
                4'd2: get_rcon = 8'h02;
                4'd3: get_rcon = 8'h04;
                4'd4: get_rcon = 8'h08;
                4'd5: get_rcon = 8'h10;
                4'd6: get_rcon = 8'h20;
                4'd7: get_rcon = 8'h40;
                default: get_rcon = 8'h00;
            endcase
        end
    endfunction

    // 15 round keys of 128 bits each
    reg [127:0] rkey [0:14];

    // State machine definition
    localparam [0:0] STATE_IDLE   = 1'b0;
    localparam [0:0] STATE_EXPAND = 1'b1;

    reg state;
    reg [3:0] cnt; // Counter to track round key calculation index (2 to 14)

    // Intermediate wires for key schedule
    wire [127:0] prev_rk   = rkey[cnt - 1'b1];
    wire [31:0]  prev_w3   = prev_rk[31:0];
    
    wire [127:0] prev2_rk  = rkey[cnt - 2'd2];
    wire [31:0]  prev2_w0  = prev2_rk[127:96];
    wire [31:0]  prev2_w1  = prev2_rk[95:64];
    wire [31:0]  prev2_w2  = prev2_rk[63:32];
    wire [31:0]  prev2_w3  = prev2_rk[31:0];

    // Select S-Box inputs based on cnt parity (even vs odd)
    // Even count = j is multiple of 8 -> RotWord
    // Odd count  = j is multiple of 8 + 4 -> No RotWord
    reg [31:0] sbox_in;
    always @(*) begin
        if (cnt[0] == 1'b0) begin
            // Even step: RotWord
            sbox_in = {prev_w3[23:16], prev_w3[15:8], prev_w3[7:0], prev_w3[31:24]};
        end else begin
            // Odd step: No RotWord
            sbox_in = prev_w3;
        end
    end

    // Instantiate exactly 4 S-Boxes shared across all 13 cycles
    wire [31:0] sbox_out;
    aes_sbox sb0 (.in_byte(sbox_in[31:24]), .out_byte(sbox_out[31:24]));
    aes_sbox sb1 (.in_byte(sbox_in[23:16]), .out_byte(sbox_out[23:16]));
    aes_sbox sb2 (.in_byte(sbox_in[15:8]),  .out_byte(sbox_out[15:8]));
    aes_sbox sb3 (.in_byte(sbox_in[7:0]),   .out_byte(sbox_out[7:0]));

    // XOR logic for key schedule word generation
    reg [31:0] temp;
    always @(*) begin
        if (cnt[0] == 1'b0) begin
            // Even step: XOR with Rcon
            temp = sbox_out ^ {get_rcon(cnt[3:1]), 24'h000000}; // cnt/2 is cnt[3:1]
        end else begin
            // Odd step: Direct sbox output
            temp = sbox_out;
        end
    end

    // Generate the 4 words for rkey[cnt]
    wire [31:0] w_out0 = prev2_w0 ^ temp;
    wire [31:0] w_out1 = prev2_w1 ^ w_out0;
    wire [31:0] w_out2 = prev2_w2 ^ w_out1;
    wire [31:0] w_out3 = prev2_w3 ^ w_out2;

    // State machine logic
    integer k;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= STATE_IDLE;
            cnt   <= 4'd0;
            ready <= 1'b0;
            for (k = 0; k < 15; k = k + 1) begin
                rkey[k] <= 128'h0;
            end
        end else begin
            case (state)
                STATE_IDLE: begin
                    if (start) begin
                        // Load Key directly into Round Keys 0 and 1
                        rkey[0] <= key[255:128];
                        rkey[1] <= key[127:0];
                        cnt     <= 4'd2;
                        ready   <= 1'b0;
                        state   <= STATE_EXPAND;
                    end else begin
                        ready   <= ready; // Maintain status
                    end
                end

                STATE_EXPAND: begin
                    rkey[cnt] <= {w_out0, w_out1, w_out2, w_out3};
                    if (cnt == 4'd14) begin
                        ready <= 1'b1;
                        state <= STATE_IDLE;
                    end else begin
                        cnt   <= cnt + 1'b1;
                    end
                end
            endcase
        end
    end

    // Map registers to the output round keys bus
    assign round_keys = {
        rkey[0],  rkey[1],  rkey[2],  rkey[3],
        rkey[4],  rkey[5],  rkey[6],  rkey[7],
        rkey[8],  rkey[9],  rkey[10], rkey[11],
        rkey[12], rkey[13], rkey[14]
    };

endmodule
