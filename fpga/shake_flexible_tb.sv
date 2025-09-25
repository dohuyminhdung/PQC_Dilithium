`timescale 1ns/1ps

module tb_sponge;
    // Parameters match DUT
    localparam LANE          = 64;
    localparam LANES         = 25;
    localparam STATE_W       = LANE * LANES;
    localparam STEP_RND      = 24;
    localparam CAPACITY      = 256;
    localparam RATE          = STATE_W - CAPACITY;
    localparam DATA_IN_BITS  = 64;
    localparam DATA_OUT_BITS = 512;
    localparam LAST_LEN = (RATE % DATA_OUT_BITS) == 0 ? DATA_OUT_BITS : (RATE % DATA_OUT_BITS);

    // Test output parameters
    localparam DIGEST_BITS    = 1280;
    logic [DIGEST_BITS-1:0] digest;
  
    // DUT signals
    logic                               clk, rst;
    logic [DATA_IN_BITS-1:0]            data_in = '0;
    logic                               in_valid = 0, in_last = 0;
    logic [$clog2(DATA_IN_BITS)-1:0]    in_last_len = 0;
    logic                               out_ready = 0;
    logic [DATA_OUT_BITS-1:0]           data_out;
    logic                               out_valid;
    logic                               out_last;
    logic [$clog2(DATA_OUT_BITS)-1:0]   out_last_len;
    logic                               in_ready;
  
    // Instantiate DUT
    sponge #(
        .LANE(LANE), 
        .LANES(LANES), 
        .STATE_W(STATE_W),
        .STEP_RND(STEP_RND), 
        .CAPACITY(CAPACITY),
        .DATA_IN_BITS(DATA_IN_BITS), 
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) dut (
        .clk        (clk), 
        .rst        (rst),
        .data_in    (data_in), 
        .in_valid   (in_valid), 
        .in_last    (in_last), 
        .in_last_len(in_last_len),
        .out_ready  (out_ready),
        .data_out   (data_out), 
        .out_valid  (out_valid), 
        .out_last   (out_last),
        .out_last_len(out_last_len), 
        .in_ready   (in_ready)
    );

    // Test instance
    int blocks = RATE / DATA_IN_BITS; // number of inputs
  
    initial clk = 0;
    always #5 clk = ~clk; // 100 MHz

    initial begin
        rst = 1; 
        repeat (5) @(posedge clk);
        rst = 0;
    end

    // Utility tasks
    task automatic send_block(input [DATA_IN_BITS-1:0] din,
                              input bit last = 0,
                              input int llen = DATA_IN_BITS);
        begin
            @(posedge clk);
            while (!in_ready) @(posedge clk);
            data_in  <= din;
            in_valid <= 1;
            in_last  <= last;
            in_last_len <= llen;

            @(posedge clk);
            data_in  <= '0;
            in_valid <= 0;
            in_last  <= 0;
            in_last_len <= 0;
        end
    endtask
    
    task automatic collect_digest(output logic [DIGEST_BITS-1:0] digest_out);
        int idx = 0;
        logic [DIGEST_BITS-1:0] tmp_digest;
        begin
            out_ready = 1;
            tmp_digest = '0;

            while(idx < DIGEST_BITS) begin
            @(posedge clk);
                if(dut.out_valid) begin
                    // write slice to tmp (blocking assign)
                    if (out_last == 0) begin
                        tmp_digest[idx +: DATA_OUT_BITS] = dut.data_out;
                        idx = idx + DATA_OUT_BITS;
                    end else begin
                        tmp_digest[idx +: LAST_LEN] = dut.data_out[0 +: LAST_LEN];
                        idx = idx + LAST_LEN;
                    end
                end
            end

            // assign once to output
            digest_out = tmp_digest;
            out_ready = 0;
            $display("Digest = %h", digest_out);
        end
    endtask
  
    initial begin : caseA_exact_fit
        wait (!rst);
        for (int i=0; i<blocks-1; i++) begin
            send_block(64'hAAAA_BBBB_CCCC_DDDD, 0, DATA_IN_BITS);
        end
        // last block, fills exactly
        send_block(64'h1111_2222_3333_4444, 1, 64);
        
        // Assert FSM flow: should see permute_mode=01 then PAD_DATA then permute->squeeze
        // (Simplified, check keccak_en pulses twice)
        assert property (@(posedge clk) disable iff(rst)
            dut.state==dut.PAD_DATA |-> dut.keccak_en==1'b1)
        else $error("PAD_DATA must assert keccak_en for exact-fit");

        // Collect digest
        collect_digest(digest);
    end
endmodule