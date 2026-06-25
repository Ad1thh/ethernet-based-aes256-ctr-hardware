`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_key_expansion
// Description:
//   Combinational Key Expansion for AES-256.
//   Expands 256-bit key into 15 round keys (1920 bits total).
//////////////////////////////////////////////////////////////////////////////////

module aes256_key_expansion (
    input  wire [255:0] key,
    output wire [1919:0] round_keys
);

    // Function to get the Round Constant (Rcon)
    function [7:0] get_rcon;
        input integer idx;
        begin
            case (idx)
                1: get_rcon = 8'h01;
                2: get_rcon = 8'h02;
                3: get_rcon = 8'h04;
                4: get_rcon = 8'h08;
                5: get_rcon = 8'h10;
                6: get_rcon = 8'h20;
                7: get_rcon = 8'h40;
                default: get_rcon = 8'h00;
            endcase
        end
    endfunction

    // 60 words of 32 bits
    wire [31:0] w[0:59];

    // First 8 words are the key itself
    assign w[0] = key[255:224];
    assign w[1] = key[223:192];
    assign w[2] = key[191:160];
    assign w[3] = key[159:128];
    assign w[4] = key[127:96];
    assign w[5] = key[95:64];
    assign w[6] = key[63:32];
    assign w[7] = key[31:0];

    // Generate the remaining 52 words
    genvar i;
    generate
        for (i = 8; i < 60; i = i + 1) begin : key_exp_step
            if (i % 8 == 0) begin
                // RotWord: shift left 1 byte circular
                wire [31:0] rot_word = {w[i-1][23:16], w[i-1][15:8], w[i-1][7:0], w[i-1][31:24]};
                wire [31:0] sub_rot_word;
                
                // Instantiate S-Boxes for RotWord
                aes_sbox sb0 (.in_byte(rot_word[31:24]), .out_byte(sub_rot_word[31:24]));
                aes_sbox sb1 (.in_byte(rot_word[23:16]), .out_byte(sub_rot_word[23:16]));
                aes_sbox sb2 (.in_byte(rot_word[15:8]),  .out_byte(sub_rot_word[15:8]));
                aes_sbox sb3 (.in_byte(rot_word[7:0]),   .out_byte(sub_rot_word[7:0]));
                
                assign w[i] = w[i-8] ^ sub_rot_word ^ {get_rcon(i/8), 24'h000000};
            end
            else if (i % 8 == 4) begin
                wire [31:0] sub_word;
                
                // Instantiate S-Boxes for SubWord (exclusive to AES-256)
                aes_sbox sb0 (.in_byte(w[i-1][31:24]), .out_byte(sub_word[31:24]));
                aes_sbox sb1 (.in_byte(w[i-1][23:16]), .out_byte(sub_word[23:16]));
                aes_sbox sb2 (.in_byte(w[i-1][15:8]),  .out_byte(sub_word[15:8]));
                aes_sbox sb3 (.in_byte(w[i-1][7:0]),   .out_byte(sub_word[7:0]));
                
                assign w[i] = w[i-8] ^ sub_word;
            end
            else begin
                assign w[i] = w[i-8] ^ w[i-1];
            end
        end
    endgenerate

    // Map the 60 words to the 15 round keys (column-major byte order preserved inside words)
    // Round Key 0: w[0..3], ..., Round Key 14: w[56..59]
    assign round_keys[1919:1792] = {w[0],  w[1],  w[2],  w[3]};
    assign round_keys[1791:1664] = {w[4],  w[5],  w[6],  w[7]};
    assign round_keys[1663:1536] = {w[8],  w[9],  w[10], w[11]};
    assign round_keys[1535:1408] = {w[12], w[13], w[14], w[15]};
    assign round_keys[1407:1280] = {w[16], w[17], w[18], w[19]};
    assign round_keys[1279:1152] = {w[20], w[21], w[22], w[23]};
    assign round_keys[1151:1024] = {w[24], w[25], w[26], w[27]};
    assign round_keys[1023:896]  = {w[28], w[29], w[30], w[31]};
    assign round_keys[895:768]   = {w[32], w[33], w[34], w[35]};
    assign round_keys[767:640]   = {w[36], w[37], w[38], w[39]};
    assign round_keys[639:512]   = {w[40], w[41], w[42], w[43]};
    assign round_keys[511:384]   = {w[44], w[45], w[46], w[47]};
    assign round_keys[383:256]   = {w[48], w[49], w[50], w[51]};
    assign round_keys[255:128]   = {w[52], w[53], w[54], w[55]};
    assign round_keys[127:0]     = {w[56], w[57], w[58], w[59]};

endmodule
