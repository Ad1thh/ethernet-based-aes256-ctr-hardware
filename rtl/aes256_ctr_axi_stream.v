`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_ctr_axi_stream
// Description:
//   AXI4-Stream 32-bit Wrapper for the AES-256 CTR core.
//   Handles 32-to-128 bit deserialization on input and 128-to-32 bit serialization on output.
//   Fully supports backpressure flow control (TREADY/TVALID) and TLAST propagation.
//////////////////////////////////////////////////////////////////////////////////

module aes256_ctr_axi_stream (
    input  wire         ACLK,
    input  wire         ARESETN,
    
    // AXI4-Stream Slave Interface (Plaintext/Ciphertext Input)
    input  wire [31:0]  S_AXIS_TDATA,
    input  wire         S_AXIS_TLAST,
    input  wire         S_AXIS_TVALID,
    output wire         S_AXIS_TREADY,
    
    // AXI4-Stream Master Interface (Ciphertext/Plaintext Output)
    output wire [31:0]  M_AXIS_TDATA,
    output wire         M_AXIS_TLAST,
    output wire         M_AXIS_TVALID,
    input  wire         M_AXIS_TREADY,
    
    // Core Engine Interface
    output wire [127:0] core_in_data,
    output wire         core_in_last,
    output wire         core_in_valid,
    input  wire         core_in_ready,
    
    input  wire [127:0] core_out_data,
    input  wire         core_out_last,
    input  wire         core_out_valid,
    output wire         core_out_ready
);

    // ==========================================
    // 1. Input Deserializer (32-bit to 128-bit)
    // ==========================================
    reg [127:0] in_buf;
    reg         in_last_reg;
    reg         in_valid_reg;
    reg [1:0]   in_count;

    // We can accept data if our buffer is empty, or if the core is consuming it this cycle
    assign S_AXIS_TREADY = !in_valid_reg || (in_valid_reg && core_in_ready);

    assign core_in_data  = in_buf;
    assign core_in_last  = in_last_reg;
    assign core_in_valid = in_valid_reg;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            in_buf       <= 128'h0;
            in_last_reg  <= 1'b0;
            in_valid_reg <= 1'b0;
            in_count     <= 2'd0;
        end else begin
            // If the core is consuming the current block, we clear or update the valid flag
            if (in_valid_reg && core_in_ready) begin
                in_valid_reg <= 1'b0;
                in_last_reg  <= 1'b0;
            end

            // Accumulate input stream
            if (S_AXIS_TVALID && S_AXIS_TREADY) begin
                in_buf[127 - 32*in_count -: 32] <= S_AXIS_TDATA;
                
                // If any beat has TLAST, mark this block as the final block
                if (S_AXIS_TLAST) begin
                    in_last_reg <= 1'b1;
                end
                
                if (in_count == 2'd3 || S_AXIS_TLAST) begin
                    in_valid_reg <= 1'b1;
                    in_count     <= 2'd0;
                end else begin
                    in_count     <= in_count + 1'b1;
                end
            end
        end
    end

    // ==========================================
    // 2. Output Serializer (128-bit to 32-bit)
    // ==========================================
    reg [127:0] out_buf;
    reg         out_last_block;
    reg         out_valid_reg;
    reg [1:0]   out_count;

    // Ready to accept new core block if buffer is empty or we are transmitting the last word
    assign core_out_ready = !out_valid_reg || (out_valid_reg && (out_count == 2'd3) && M_AXIS_TREADY);

    // Map output stream
    assign M_AXIS_TDATA  = out_buf[127 - 32*out_count -: 32];
    assign M_AXIS_TLAST  = (out_count == 2'd3) ? out_last_block : 1'b0;
    assign M_AXIS_TVALID = out_valid_reg;

    always @(posedge ACLK) begin
        if (!ARESETN) begin
            out_buf        <= 128'h0;
            out_last_block <= 1'b0;
            out_valid_reg  <= 1'b0;
            out_count      <= 2'd0;
        end else begin
            if (core_out_valid && core_out_ready) begin
                out_buf        <= core_out_data;
                out_last_block <= core_out_last;
                out_valid_reg  <= 1'b1;
                out_count      <= 2'd0;
            end else if (M_AXIS_TVALID && M_AXIS_TREADY) begin
                if (out_count == 2'd3) begin
                    out_valid_reg  <= 1'b0;
                    out_last_block <= 1'b0;
                    out_count      <= 2'd0;
                end else begin
                    out_count      <= out_count + 1'b1;
                end
            end
        end
    end

endmodule
