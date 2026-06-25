`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes_round_enc
// Description:
//   A single AES encryption round.
//   Performs SubBytes, ShiftRows, MixColumns (optional), and AddRoundKey.
//////////////////////////////////////////////////////////////////////////////////

module aes_round_enc # (
    parameter integer LAST_ROUND = 0
) (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    // 1. SubBytes: Instantiate 16 S-Boxes
    wire [127:0] sub_state;
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : sbox_loop
            aes_sbox sb (
                .in_byte(state_in[127 - 8*i -: 8]),
                .out_byte(sub_state[127 - 8*i -: 8])
            );
        end
    endgenerate

    // 2. ShiftRows: Byte-level circular shift permutation
    wire [127:0] shift_state;
    assign shift_state = {
        sub_state[127:120], // Byte 0
        sub_state[87:80],   // Byte 1
        sub_state[47:40],   // Byte 2
        sub_state[7:0],     // Byte 3
        sub_state[95:88],   // Byte 4
        sub_state[55:48],   // Byte 5
        sub_state[15:8],    // Byte 6
        sub_state[103:96],  // Byte 7
        sub_state[63:56],   // Byte 8
        sub_state[23:16],   // Byte 9
        sub_state[111:104], // Byte 10
        sub_state[71:64],   // Byte 11
        sub_state[31:24],   // Byte 12
        sub_state[119:112], // Byte 13
        sub_state[79:72],   // Byte 14
        sub_state[39:32]    // Byte 15
    };

    // 3. MixColumns (only if NOT the last round)
    wire [127:0] mixed_state;
    
    if (LAST_ROUND == 0) begin : mix_col_inst
        aes_mix_columns mc (
            .state_in(shift_state),
            .state_out(mixed_state)
        );
        // 4. AddRoundKey
        assign state_out = mixed_state ^ round_key;
    end else begin : last_round_inst
        // 4. AddRoundKey directly after ShiftRows (no MixColumns)
        assign state_out = shift_state ^ round_key;
    end

endmodule


//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes_mix_columns
// Description:
//   MixColumns transformation operating on four 32-bit columns.
//////////////////////////////////////////////////////////////////////////////////
module aes_mix_columns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // GF(2^8) multiplication by 2
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = (b[7] == 1'b1) ? ((b << 1) ^ 8'h1b) : (b << 1);
        end
    endfunction

    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : mix_col_loop
            // Extract column elements (column-major order)
            wire [7:0] c0 = state_in[127 - 32*i : 120 - 32*i];
            wire [7:0] c1 = state_in[119 - 32*i : 112 - 32*i];
            wire [7:0] c2 = state_in[111 - 32*i : 104 - 32*i];
            wire [7:0] c3 = state_in[103 - 32*i : 96 - 32*i];

            // Perform multiplication with matrix and sum in GF(2^8)
            assign state_out[127 - 32*i : 120 - 32*i] = xtime(c0) ^ (xtime(c1) ^ c1) ^ c2 ^ c3;
            assign state_out[119 - 32*i : 112 - 32*i] = c0 ^ xtime(c1) ^ (xtime(c2) ^ c2) ^ c3;
            assign state_out[111 - 32*i : 104 - 32*i] = c0 ^ c1 ^ xtime(c2) ^ (xtime(c3) ^ c3);
            assign state_out[103 - 32*i : 96 - 32*i]   = (xtime(c0) ^ c0) ^ c1 ^ c2 ^ xtime(c3);
        end
    endgenerate

endmodule
