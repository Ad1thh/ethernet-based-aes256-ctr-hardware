`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_ctr_core
// Description:
//   Core AES-256 CTR (Counter) mode hardware engine.
//   Encrypts the counter stream and XORs it with the data.
//   Saves logic by sharing the encryption pipeline for both Encrypt/Decrypt.
//   Features a 15-stage delay line to align data with the pipeline latency.
//   Supports backpressure stall/flow control, automatic pipeline flushing,
//   and TLAST packet boundary propagation.
//////////////////////////////////////////////////////////////////////////////////

module aes256_ctr_core (
    input  wire         clk,
    input  wire         rst_n,
    
    // Configuration
    input  wire [255:0] key,
    input  wire [127:0] iv,
    input  wire         start, // Initialize counter to IV
    
    // Input Stream
    input  wire [127:0] in_data,
    input  wire         in_last,
    input  wire         in_valid,
    output wire         in_ready,
    
    // Output Stream
    output wire [127:0] out_data,
    output wire         out_last,
    output wire         out_valid,
    input  wire         out_ready
);

    // 128-bit counter register
    reg [127:0] ctr_reg;

    // 15-stage shift registers for data, validity, and TLAST delay matching
    reg [127:0] data_delay [0:14];
    reg         valid_pipe [0:14];
    reg         last_pipe  [0:14];

    // Key Expansion Instantiation
    wire [1919:0] round_keys;
    wire          key_ready;
    aes256_key_expansion key_expand_inst (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .key(key),
        .round_keys(round_keys),
        .ready(key_ready)
    );

    // Flow Control & Pipeline Enable Logic
    // Stall pipeline only if output contains valid data and downstream is not ready
    wire pipeline_en = !(valid_pipe[14] && !out_ready);
    
    // Check if there is any valid data currently inside stages 0 to 13 of the pipeline
    reg pipeline_has_data;
    integer j;
    always @(*) begin
        pipeline_has_data = 1'b0;
        for (j = 0; j < 14; j = j + 1) begin
            if (valid_pipe[j]) pipeline_has_data = 1'b1;
        end
    end

    // The pipeline shifts if it is not stalled, AND we have either new input OR data to flush, AND key is ready
    wire shift_en = pipeline_en && (in_valid || pipeline_has_data) && key_ready;

    // Input is ready if the pipeline is not stalled and the key expander is ready
    assign in_ready = pipeline_en && key_ready;

    // Counter Management
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            ctr_reg <= 128'h0;
        end else if (start) begin
            ctr_reg <= iv;
        end else if (shift_en && in_valid) begin
            ctr_reg <= ctr_reg + 1'b1;
        end
    end

    // Select input to the AES pipeline:
    // If we have valid input, feed the current counter. Else, feed a dummy value (bubble).
    wire [127:0] aes_in = in_valid ? ctr_reg : 128'h0;

    // Instantiate Pipelined AES-256 Core
    wire [127:0] aes_out;
    aes256_encrypt_pipeline aes_pipeline_inst (
        .clk(clk),
        .rst_n(rst_n),
        .en(shift_en),
        .round_keys(round_keys),
        .state_in(aes_in),
        .state_out(aes_out)
    );

    // Delay lines shifting
    integer k;
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            for (k = 0; k < 15; k = k + 1) begin
                data_delay[k] <= 128'h0;
                valid_pipe[k] <= 1'b0;
                last_pipe[k]  <= 1'b0;
            end
        end else if (shift_en) begin
            // Shift data
            data_delay[0] <= in_valid ? in_data : 128'h0;
            for (k = 1; k < 15; k = k + 1) begin
                data_delay[k] <= data_delay[k-1];
            end
            
            // Shift validity
            valid_pipe[0] <= in_valid;
            for (k = 1; k < 15; k = k + 1) begin
                valid_pipe[k] <= valid_pipe[k-1];
            end

            // Shift TLAST
            last_pipe[0] <= in_valid ? in_last : 1'b0;
            for (k = 1; k < 15; k = k + 1) begin
                last_pipe[k] <= last_pipe[k-1];
            end
        end else if (out_ready && valid_pipe[14]) begin
            // If we aren't shifting, but downstream consumed the final output block,
            // we clear output validity and last indicators
            valid_pipe[14] <= 1'b0;
            last_pipe[14]  <= 1'b0;
        end
    end

    // Output mapping
    assign out_valid = valid_pipe[14];
    assign out_last  = last_pipe[14];
    assign out_data  = data_delay[14] ^ aes_out;

endmodule
