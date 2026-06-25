`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: aes256_ctr_top
// Description:
//   Top-level IP wrapper for the Hardware AES-256 CTR system.
//   Exposes:
//     - S_AXI (AXI4-Lite Slave): Key configuration, IV, control, and zeroization.
//     - S_AXIS (AXI4-Stream Slave): Plaintext/ciphertext input (32-bit).
//     - M_AXIS (AXI4-Stream Master): Ciphertext/plaintext output (32-bit).
//     - panic_button (External Input): Instantly wipes key registers if asserted high.
//////////////////////////////////////////////////////////////////////////////////

module aes256_ctr_top # (
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 6
) (
    // Global Clock and Reset
    input  wire                                  S_AXI_ACLK,
    input  wire                                  S_AXI_ARESETN,

    // AXI4-Lite Slave Interface (Control/Config)
    input  wire [C_S_AXI_ADDR_WIDTH-1 : 0]        S_AXI_AWADDR,
    input  wire [2 : 0]                          S_AXI_AWPROT,
    input  wire                                  S_AXI_AWVALID,
    output wire                                  S_AXI_AWREADY,
    input  wire [C_S_AXI_DATA_WIDTH-1 : 0]        S_AXI_WDATA,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1 : 0]    S_AXI_WSTRB,
    input  wire                                  S_AXI_WVALID,
    output wire                                  S_AXI_WREADY,
    output wire [1 : 0]                          S_AXI_BRESP,
    output wire                                  S_AXI_BVALID,
    input  wire                                  S_AXI_BREADY,
    input  wire [C_S_AXI_ADDR_WIDTH-1 : 0]        S_AXI_ARADDR,
    input  wire [2 : 0]                          S_AXI_ARPROT,
    input  wire                                  S_AXI_ARVALID,
    output wire                                  S_AXI_ARREADY,
    output wire [C_S_AXI_DATA_WIDTH-1 : 0]        S_AXI_RDATA,
    output wire [1 : 0]                          S_AXI_RRESP,
    output wire                                  S_AXI_RVALID,
    input  wire                                  S_AXI_RREADY,

    // AXI4-Stream Slave Interface (Data Input)
    input  wire [31:0]                           S_AXIS_TDATA,
    input  wire                                  S_AXIS_TLAST,
    input  wire                                  S_AXIS_TVALID,
    output wire                                  S_AXIS_TREADY,

    // AXI4-Stream Master Interface (Data Output)
    output wire [31:0]                           M_AXIS_TDATA,
    output wire                                  M_AXIS_TLAST,
    output wire                                  M_AXIS_TVALID,
    input  wire                                  M_AXIS_TREADY,

    // Hardware Security Interface
    input  wire                                  panic_button
);

    // ==========================================
    // AXI-Lite Registers Definitions
    // ==========================================
    reg [C_S_AXI_ADDR_WIDTH-1 : 0] axi_awaddr;
    reg                            axi_awready;
    reg                            axi_wready;
    reg [1 : 0]                    axi_bresp;
    reg                            axi_bvalid;
    reg [C_S_AXI_ADDR_WIDTH-1 : 0] axi_araddr;
    reg                            axi_arready;
    reg [C_S_AXI_DATA_WIDTH-1 : 0] axi_rdata;
    reg [1 : 0]                    axi_rresp;
    reg                            axi_rvalid;

    // Registers Map:
    // REG 0-7  (0x00-0x1C): 256-bit Key
    // REG 8-11 (0x20-0x2C): 128-bit IV
    // REG 12   (0x30)     : Control/Strobe (bit 0 = start, bit 1 = zeroize)
    reg [31:0] slv_reg0;
    reg [31:0] slv_reg1;
    reg [31:0] slv_reg2;
    reg [31:0] slv_reg3;
    reg [31:0] slv_reg4;
    reg [31:0] slv_reg5;
    reg [31:0] slv_reg6;
    reg [31:0] slv_reg7;
    reg [31:0] slv_reg8;
    reg [31:0] slv_reg9;
    reg [31:0] slv_reg10;
    reg [31:0] slv_reg11;
    reg [31:0] slv_reg12;

    assign S_AXI_AWREADY = axi_awready;
    assign S_AXI_WREADY  = axi_wready;
    assign S_AXI_BRESP   = axi_bresp;
    assign S_AXI_BVALID  = axi_bvalid;
    assign S_AXI_ARREADY = axi_arready;
    assign S_AXI_RDATA   = axi_rdata;
    assign S_AXI_RRESP   = axi_rresp;
    assign S_AXI_RVALID  = axi_rvalid;

    wire slv_reg_wren = axi_wready && S_AXI_WVALID && axi_awready && S_AXI_AWVALID;
    
    // Hardware Debouncer for the Physical Panic Button
    // Requires the input to remain stable for 1,000,000 clock cycles (10 ms at 100 MHz)
    reg [19:0] debounce_counter;
    reg        debounced_panic_button;
    always @(posedge S_AXI_ACLK) begin
        if (S_AXI_ARESETN == 1'b0) begin
            debounce_counter       <= 20'h0;
            debounced_panic_button <= 1'b0;
        end else begin
            if (panic_button) begin
                if (debounce_counter < 20'd1000000) begin
                    debounce_counter <= debounce_counter + 1'b1;
                end else begin
                    debounced_panic_button <= 1'b1;
                end
            end else begin
                debounce_counter       <= 20'h0;
                debounced_panic_button <= 1'b0;
            end
        end
    end

    // Zeroization logic: triggered by the debounced hardware panic button or register write
    wire do_zeroize = debounced_panic_button || (slv_reg_wren && (axi_awaddr[5:2] == 4'hC) && S_AXI_WDATA[1]);

    // AXI-Lite Write Handshake and Register Assignment
    always @(posedge S_AXI_ACLK) begin
        if (S_AXI_ARESETN == 1'b0) begin
            axi_awready <= 1'b0;
            axi_wready  <= 1'b0;
            axi_bvalid  <= 1'b0;
            axi_bresp   <= 2'b0;
            axi_awaddr  <= 0;
        end else begin
            // Address Write Ready
            if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID) begin
                axi_awready <= 1'b1;
                axi_awaddr  <= S_AXI_AWADDR;
            end else begin
                axi_awready <= 1'b0;
            end

            // Data Write Ready
            if (~axi_wready && S_AXI_WVALID && S_AXI_AWVALID) begin
                axi_wready <= 1'b1;
            end else begin
                axi_wready <= 1'b0;
            end

            // Write Response (BVALID)
            if (axi_awready && S_AXI_AWVALID && ~axi_bvalid && axi_wready && S_AXI_WVALID) begin
                axi_bvalid <= 1'b1;
                axi_bresp  <= 2'b0; // OKAY response
            end else if (S_AXI_BREADY && axi_bvalid) begin
                axi_bvalid <= 1'b0;
            end
        end
    end

    // Write data to register file
    always @(posedge S_AXI_ACLK) begin
        if (S_AXI_ARESETN == 1'b0 || do_zeroize) begin
            slv_reg0  <= 32'h0;
            slv_reg1  <= 32'h0;
            slv_reg2  <= 32'h0;
            slv_reg3  <= 32'h0;
            slv_reg4  <= 32'h0;
            slv_reg5  <= 32'h0;
            slv_reg6  <= 32'h0;
            slv_reg7  <= 32'h0;
            slv_reg8  <= 32'h0;
            slv_reg9  <= 32'h0;
            slv_reg10 <= 32'h0;
            slv_reg11 <= 32'h0;
            slv_reg12 <= 32'h0;
        end else if (slv_reg_wren) begin
            case (axi_awaddr[5:2])
                4'h0: slv_reg0  <= S_AXI_WDATA;
                4'h1: slv_reg1  <= S_AXI_WDATA;
                4'h2: slv_reg2  <= S_AXI_WDATA;
                4'h3: slv_reg3  <= S_AXI_WDATA;
                4'h4: slv_reg4  <= S_AXI_WDATA;
                4'h5: slv_reg5  <= S_AXI_WDATA;
                4'h6: slv_reg6  <= S_AXI_WDATA;
                4'h7: slv_reg7  <= S_AXI_WDATA;
                4'h8: slv_reg8  <= S_AXI_WDATA;
                4'h9: slv_reg9  <= S_AXI_WDATA;
                4'hA: slv_reg10 <= S_AXI_WDATA;
                4'hB: slv_reg11 <= S_AXI_WDATA;
                4'hC: slv_reg12 <= S_AXI_WDATA;
                default: ;
            endcase
        end
    end

    // Self-clearing Start Strobe
    reg start_strobe;
    always @(posedge S_AXI_ACLK) begin
        if (S_AXI_ARESETN == 1'b0 || do_zeroize) begin
            start_strobe <= 1'b0;
        end else begin
            if (slv_reg_wren && (axi_awaddr[5:2] == 4'hC) && S_AXI_WDATA[0]) begin
                start_strobe <= 1'b1;
            end else begin
                start_strobe <= 1'b0;
            end
        end
    end

    // AXI-Lite Read Handshake
    always @(posedge S_AXI_ACLK) begin
        if (S_AXI_ARESETN == 1'b0) begin
            axi_arready <= 1'b0;
            axi_araddr  <= 0;
            axi_rvalid  <= 1'b0;
            axi_rresp   <= 2'b0;
            axi_rdata   <= 32'h0;
        end else begin
            // Read Address Ready
            if (~axi_arready && S_AXI_ARVALID) begin
                axi_arready <= 1'b1;
                axi_araddr  <= S_AXI_ARADDR;
            end else begin
                axi_arready <= 1'b0;
            end

            // Read Data Valid (RVALID)
            if (axi_arready && S_AXI_ARVALID && ~axi_rvalid) begin
                axi_rvalid <= 1'b1;
                axi_rresp  <= 2'b0; // OKAY response
                
                // Read Data Multiplexer
                case (axi_araddr[5:2])
                    4'h0: axi_rdata  <= slv_reg0;
                    4'h1: axi_rdata  <= slv_reg1;
                    4'h2: axi_rdata  <= slv_reg2;
                    4'h3: axi_rdata  <= slv_reg3;
                    4'h4: axi_rdata  <= slv_reg4;
                    4'h5: axi_rdata  <= slv_reg5;
                    4'h6: axi_rdata  <= slv_reg6;
                    4'h7: axi_rdata  <= slv_reg7;
                    4'h8: axi_rdata  <= slv_reg8;
                    4'h9: axi_rdata  <= slv_reg9;
                    4'hA: axi_rdata  <= slv_reg10;
                    4'hB: axi_rdata  <= slv_reg11;
                    4'hC: axi_rdata  <= slv_reg12;
                    default: axi_rdata <= 32'hDEADBEEF;
                endcase
            end else if (S_AXI_RREADY && axi_rvalid) begin
                axi_rvalid <= 1'b0;
            end
        end
    end

    // ==========================================
    // Instantiations of Core and Stream Wrapper
    // ==========================================
    wire [255:0] key_bus = {slv_reg0, slv_reg1, slv_reg2, slv_reg3, slv_reg4, slv_reg5, slv_reg6, slv_reg7};
    wire [127:0] iv_bus  = {slv_reg8, slv_reg9, slv_reg10, slv_reg11};

    wire [127:0] core_in_data;
    wire         core_in_last;
    wire         core_in_valid;
    wire         core_in_ready;
    
    wire [127:0] core_out_data;
    wire         core_out_last;
    wire         core_out_valid;
    wire         core_out_ready;

    // AXI-Stream Deserializer/Serializer Wrapper
    aes256_ctr_axi_stream stream_wrapper_inst (
        .ACLK(S_AXI_ACLK),
        .ARESETN(S_AXI_ARESETN),
        
        .S_AXIS_TDATA(S_AXIS_TDATA),
        .S_AXIS_TLAST(S_AXIS_TLAST),
        .S_AXIS_TVALID(S_AXIS_TVALID),
        .S_AXIS_TREADY(S_AXIS_TREADY),
        
        .M_AXIS_TDATA(M_AXIS_TDATA),
        .M_AXIS_TLAST(M_AXIS_TLAST),
        .M_AXIS_TVALID(M_AXIS_TVALID),
        .M_AXIS_TREADY(M_AXIS_TREADY),
        
        .core_in_data(core_in_data),
        .core_in_last(core_in_last),
        .core_in_valid(core_in_valid),
        .core_in_ready(core_in_ready),
        
        .core_out_data(core_out_data),
        .core_out_last(core_out_last),
        .core_out_valid(core_out_valid),
        .core_out_ready(core_out_ready)
    );

    // CTR Core Engine
    aes256_ctr_core core_inst (
        .clk(S_AXI_ACLK),
        .rst_n(S_AXI_ARESETN && !do_zeroize), // Reset core instantly if zeroized
        
        .key(key_bus),
        .iv(iv_bus),
        .start(start_strobe),
        
        .in_data(core_in_data),
        .in_last(core_in_last),
        .in_valid(core_in_valid),
        .in_ready(core_in_ready),
        
        .out_data(core_out_data),
        .out_last(core_out_last),
        .out_valid(core_out_valid),
        .out_ready(core_out_ready)
    );

endmodule
