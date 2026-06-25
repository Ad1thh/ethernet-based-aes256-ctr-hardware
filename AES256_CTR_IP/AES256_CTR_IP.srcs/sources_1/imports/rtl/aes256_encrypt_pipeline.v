`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_encrypt_pipeline
// Description:
//   14-stage pipelined AES-256 encryption datapath.
//   Includes an enable (en) port for pipeline stalling / flow control.
//   Latency: 15 clock cycles (including input and output registers).
//   Throughput: 1 block (128-bit) per clock cycle.
//////////////////////////////////////////////////////////////////////////////////

module aes256_encrypt_pipeline (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         en,
    input  wire [1919:0] round_keys,
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // Pipeline registers for state
    reg [127:0] state_reg [0:14];

    // Stage 0: Input Register
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            state_reg[0] <= 128'h0;
        end else if (en) begin
            state_reg[0] <= state_in;
        end
    end

    // Initial Round Key addition (Round 0)
    // Key 0 is round_keys[1919:1792]
    wire [127:0] state_rk0 = state_reg[0] ^ round_keys[1919:1792];

    // State intermediate wires
    wire [127:0] round_in [1:14];
    wire [127:0] round_out [1:14];

    // Connect round inputs
    assign round_in[1] = state_rk0;
    
    genvar r;
    generate
        for (r = 2; r <= 14; r = r + 1) begin : round_in_connections
            assign round_in[r] = state_reg[r-1];
        end
    endgenerate

    // Instantiate Rounds 1 to 13 (Standard Rounds)
    generate
        for (r = 1; r <= 13; r = r + 1) begin : standard_rounds
            aes_round_enc #(.LAST_ROUND(0)) round_inst (
                .state_in(round_in[r]),
                .round_key(round_keys[1919 - 128*r -: 128]),
                .state_out(round_out[r])
            );

            always @(posedge clk or negedge rst_n) begin
                if (~rst_n) begin
                    state_reg[r] <= 128'h0;
                end else if (en) begin
                    state_reg[r] <= round_out[r];
                end
            end
        end
    endgenerate

    // Instantiate Round 14 (Final Round - No MixColumns)
    aes_round_enc #(.LAST_ROUND(1)) final_round_inst (
        .state_in(round_in[14]),
        .round_key(round_keys[127:0]),
        .state_out(round_out[14])
    );

    // Stage 14: Output Register
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            state_reg[14] <= 128'h0;
        end else if (en) begin
            state_reg[14] <= round_out[14];
        end
    end

    assign state_out = state_reg[14];

endmodule
