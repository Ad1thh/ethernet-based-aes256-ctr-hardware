`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Module Name: tb_aes256_ctr_ip
// Description:
//   Self-checking behavioral testbench for the aes256_ctr_top IP core.
//   Verifies the AXI-Lite register writes, AXI-Stream serialization/deserialization,
//   and the correct functionality of encryption and decryption in CTR mode.
//////////////////////////////////////////////////////////////////////////////////

module tb_aes256_ctr_ip;

    // Clock and Reset
    reg clk;
    reg rst_n;

    // AXI-Lite Interface
    reg [5:0]   s_axi_awaddr;
    reg         s_axi_awvalid;
    wire        s_axi_awready;
    reg [31:0]  s_axi_wdata;
    reg [3:0]   s_axi_wstrb;
    reg         s_axi_wvalid;
    wire        s_axi_wready;
    wire [1:0]  s_axi_bresp;
    wire        s_axi_bvalid;
    reg         s_axi_bready;
    
    reg [5:0]   s_axi_araddr;
    reg         s_axi_arvalid;
    wire        s_axi_arready;
    wire [31:0] s_axi_rdata;
    wire [1:0]  s_axi_rresp;
    wire        s_axi_rvalid;
    reg         s_axi_rready;

    // AXI-Stream Input
    reg [31:0]  s_axis_tdata;
    reg         s_axis_tlast;
    reg         s_axis_tvalid;
    wire        s_axis_tready;

    // AXI-Stream Output
    wire [31:0] m_axis_tdata;
    wire        m_axis_tlast;
    wire        m_axis_tvalid;
    reg         m_axis_tready;

    // Hardware Security
    reg         panic_button;

    // Instantiate Unit Under Test (UUT)
    aes256_ctr_top #(
        .C_S_AXI_DATA_WIDTH(32),
        .C_S_AXI_ADDR_WIDTH(6),
        .DEBOUNCE_LIMIT(5)
    ) uut (
        .S_AXI_ACLK(clk),
        .S_AXI_ARESETN(rst_n),
        .S_AXI_AWADDR(s_axi_awaddr),
        .S_AXI_AWPROT(3'b000),
        .S_AXI_AWVALID(s_axi_awvalid),
        .S_AXI_AWREADY(s_axi_awready),
        .S_AXI_WDATA(s_axi_wdata),
        .S_AXI_WSTRB(s_axi_wstrb),
        .S_AXI_WVALID(s_axi_wvalid),
        .S_AXI_WREADY(s_axi_wready),
        .S_AXI_BRESP(s_axi_bresp),
        .S_AXI_BVALID(s_axi_bvalid),
        .S_AXI_BREADY(s_axi_bready),
        .S_AXI_ARADDR(s_axi_araddr),
        .S_AXI_ARPROT(3'b000),
        .S_AXI_ARVALID(s_axi_arvalid),
        .S_AXI_ARREADY(s_axi_arready),
        .S_AXI_RDATA(s_axi_rdata),
        .S_AXI_RRESP(s_axi_rresp),
        .S_AXI_RVALID(s_axi_rvalid),
        .S_AXI_RREADY(s_axi_rready),
        
        .S_AXIS_TDATA(s_axis_tdata),
        .S_AXIS_TLAST(s_axis_tlast),
        .S_AXIS_TVALID(s_axis_tvalid),
        .S_AXIS_TREADY(s_axis_tready),
        
        .M_AXIS_TDATA(m_axis_tdata),
        .M_AXIS_TLAST(m_axis_tlast),
        .M_AXIS_TVALID(m_axis_tvalid),
        .M_AXIS_TREADY(m_axis_tready),
        
        .panic_button(panic_button)
    );

    // Clock Generation (100 MHz)
    always #5 clk = ~clk;

    // Stream logging block
    always @(posedge clk) begin
        if (s_axis_tvalid && s_axis_tready) begin
            $display("[STREAM_IN %d ns] beat data=%h tlast=%b count=%d", 
                     $time, s_axis_tdata, s_axis_tlast, uut.stream_wrapper_inst.in_count);
        end
        if (m_axis_tvalid && m_axis_tready) begin
            $display("[STREAM_OUT %d ns] beat data=%h tlast=%b count=%d", 
                     $time, m_axis_tdata, m_axis_tlast, uut.stream_wrapper_inst.out_count);
        end
    end

    // Debug logging block
    reg prev_key_ready;
    always @(posedge clk) begin
        prev_key_ready <= uut.core_inst.key_ready;
        if (uut.core_inst.shift_en || uut.core_inst.start || uut.core_inst.out_valid || uut.core_inst.key_ready != prev_key_ready) begin
            $display("[DEBUG %d ns] rst_n=%b start=%b key_ready=%b shift_en=%b in_valid=%b in_ready=%b in_data=%h ctr=%h aes_out=%h out_valid=%b out_ready=%b out_data=%h",
                     $time, rst_n, uut.core_inst.start, uut.core_inst.key_ready, uut.core_inst.shift_en, uut.core_inst.in_valid, uut.core_inst.in_ready, uut.core_inst.in_data, uut.core_inst.ctr_reg, uut.core_inst.aes_out, uut.core_inst.out_valid, uut.core_inst.out_ready, uut.core_inst.out_data);
        end
    end

    // Test Variables
    reg [127:0] test_plaintext_1;
    reg [127:0] test_plaintext_2;
    reg [255:0] test_key;
    reg [127:0] test_iv;
    
    reg [127:0] captured_ciphertext_1;
    reg [127:0] captured_ciphertext_2;
    reg [127:0] decrypted_plaintext_1;
    reg [127:0] decrypted_plaintext_2;
    reg         l1;
    reg         l2;

    // AXI-Lite Write Helper Task
    task axi_write;
        input [5:0] addr;
        input [31:0] data;
        begin
            @(posedge clk);
            s_axi_awaddr  = addr;
            s_axi_awvalid = 1'b1;
            s_axi_wdata   = data;
            s_axi_wstrb   = 4'hf;
            s_axi_wvalid  = 1'b1;
            s_axi_bready  = 1'b1;

            fork
                begin
                    while (!s_axi_awready) @(posedge clk);
                end
                begin
                    while (!s_axi_wready) @(posedge clk);
                end
            join

            @(posedge clk);
            s_axi_awvalid = 1'b0;
            s_axi_wvalid  = 1'b0;
            
            while (!s_axi_bvalid) @(posedge clk);
            @(posedge clk);
            s_axi_bready  = 1'b0;
            #2; // Small timing gap
        end
    endtask

    // AXI-Stream Send Block (128-bit as four 32-bit beats)
    task stream_send_block;
        input [127:0] block;
        input is_last;
        integer b;
        begin
            for (b = 0; b < 4; b = b + 1) begin
                s_axis_tvalid <= 1'b1;
                s_axis_tdata  <= block[127 - 32*b -: 32];
                s_axis_tlast  <= (b == 3) ? is_last : 1'b0;
                
                @(posedge clk);
                while (!s_axis_tready) @(posedge clk);
            end
            #1;
            s_axis_tvalid <= 1'b0;
            s_axis_tlast  <= 1'b0;
            s_axis_tdata  <= 32'h0;
        end
    endtask

    // AXI-Stream Receive Block (128-bit from four 32-bit beats)
    task stream_recv_block;
        output [127:0] block;
        output is_last;
        integer b;
        reg [31:0] val;
        begin
            m_axis_tready = 1'b1;
            for (b = 0; b < 4; b = b + 1) begin
                @(posedge clk);
                while (!m_axis_tvalid) @(posedge clk);
                val = m_axis_tdata;
                block[127 - 32*b -: 32] = val;
                if (b == 3) begin
                    is_last = m_axis_tlast;
                end
            end
            #1 m_axis_tready = 1'b0;
        end
    endtask

    // Main Simulation Flow
    initial begin
        // Initialize inputs
        clk           = 0;
        rst_n         = 0;
        s_axi_awaddr  = 0;
        s_axi_awvalid = 0;
        s_axi_wdata   = 0;
        s_axi_wstrb   = 0;
        s_axi_wvalid  = 0;
        s_axi_bready  = 0;
        s_axi_araddr  = 0;
        s_axi_arvalid = 0;
        s_axi_rready  = 0;
        s_axis_tdata  = 0;
        s_axis_tlast  = 0;
        s_axis_tvalid = 0;
        m_axis_tready = 0;
        panic_button  = 0;

        // Vector values
        test_plaintext_1 = 128'h00112233445566778899aabbccddeeff;
        test_plaintext_2 = 128'hffeeddccbbaa99887766554433221100;
        test_key         = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        test_iv          = 128'hf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;

        $display("[TB] Resetting system...");
        #20;
        rst_n = 1;
        #20;

        $display("[TB] Programming AES-256 Key via AXI-Lite...");
        axi_write(6'h00, test_key[255:224]);
        axi_write(6'h04, test_key[223:192]);
        axi_write(6'h08, test_key[191:160]);
        axi_write(6'h0c, test_key[159:128]);
        axi_write(6'h10, test_key[127:96]);
        axi_write(6'h14, test_key[95:64]);
        axi_write(6'h18, test_key[63:32]);
        axi_write(6'h1c, test_key[31:0]);

        $display("[TB] Programming IV/Counter...");
        axi_write(6'h20, test_iv[127:96]);
        axi_write(6'h24, test_iv[95:64]);
        axi_write(6'h28, test_iv[63:32]);
        axi_write(6'h2c, test_iv[31:0]);

        $display("[TB] Pulsing Start Strobe (REG 12)...");
        axi_write(6'h30, 32'h00000001); // Bit 0 = start

        #200;

        $display("[TB] Phase 1: Sending Plaintext Blocks (Encryption)...");
        fork
            begin
                stream_send_block(test_plaintext_1, 1'b0);
                stream_send_block(test_plaintext_2, 1'b1); // Final block of the file
            end
            begin
                stream_recv_block(captured_ciphertext_1, l1);
                $display("[TB] Ciphertext Block 1: %h (Last = %b)", captured_ciphertext_1, l1);
                stream_recv_block(captured_ciphertext_2, l2);
                $display("[TB] Ciphertext Block 2: %h (Last = %b)", captured_ciphertext_2, l2);
            end
        join

        #200;

        $display("[TB] Phase 2: Decrypting Ciphertext back to Plaintext...");
        $display("[TB] Resetting counter to initial IV...");
        axi_write(6'h30, 32'h00000001); // Pulsing start strobe again to reset counter
        #200;

        fork
            begin
                stream_send_block(captured_ciphertext_1, 1'b0);
                stream_send_block(captured_ciphertext_2, 1'b1);
            end
            begin
                stream_recv_block(decrypted_plaintext_1, l1);
                $display("[TB] Decrypted Block 1: %h (Last = %b)", decrypted_plaintext_1, l1);
                stream_recv_block(decrypted_plaintext_2, l2);
                $display("[TB] Decrypted Block 2: %h (Last = %b)", decrypted_plaintext_2, l2);
            end
        join

        // Verification Checks
        $display("[TB] Verifying outputs...");
        if (decrypted_plaintext_1 == test_plaintext_1 && decrypted_plaintext_2 == test_plaintext_2) begin
            $display("[TB] ========================================");
            $display("[TB] VERIFICATION SUCCESS: Data recovered!");
            $display("[TB] ========================================");
        end else begin
            $display("[TB] ========================================");
            $display("[TB] ERROR: Verification failed!");
            $display("[TB] Plaintext 1: %h, Decrypted: %h", test_plaintext_1, decrypted_plaintext_1);
            $display("[TB] Plaintext 2: %h, Decrypted: %h", test_plaintext_2, decrypted_plaintext_2);
            $display("[TB] ========================================");
        end

        // Test Hardware Zeroization (Panic Button)
        #50;
        $display("[TB] Testing Hardware Security Key Zeroization (Panic Button)...");
        panic_button = 1;
        #100;
        panic_button = 0;
        #10;
        
        // Try to read back key from AXI-Lite
        $display("[TB] Reading back Key register after panic button pulse...");
        s_axi_araddr  = 6'h00; // Key register 0
        s_axi_arvalid = 1'b1;
        s_axi_rready  = 1'b1;
        @(posedge clk);
        while (!s_axi_arready) @(posedge clk);
        @(posedge clk);
        s_axi_arvalid = 1'b0;
        while (!s_axi_rvalid) @(posedge clk);
        $display("[TB] Key Register 0 Value read: %h (Expected: 00000000 due to Zeroization)", s_axi_rdata);
        if (s_axi_rdata == 32'h0) begin
            $display("[TB] ZEROIZATION VERIFIED: Key registers cleared successfully.");
        end else begin
            $display("[TB] ERROR: Zeroization failed, key remains in memory.");
        end
        s_axi_rready = 1'b0;

        #100;
        $display("[TB] Simulation completed.");
        $finish;
    end

endmodule
