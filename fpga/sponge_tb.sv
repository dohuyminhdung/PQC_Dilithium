`timescale 1ns/1ps

module tb_sponge;
  
  // Parameters match DUT
  // ------------------------------------------------------------
  localparam LANE          = 64;
  localparam LANES         = 25;
  localparam STATE_W       = LANE * LANES;
  localparam STEP_RND      = 24;
  localparam CAPACITY      = 512;
  localparam RATE          = STATE_W - CAPACITY;
  localparam DATA_IN_BITS  = 64;
  localparam DATA_OUT_BITS = 32;

  localparam DIGEST_BITS    = 256;
  // ------------------------------------------------------------
  // DUT signals
  // ------------------------------------------------------------
  logic                             clk, rst;
  logic [DATA_IN_BITS-1:0]          data_in;
  logic                             in_valid, in_last;
  logic [$clog2(DATA_IN_BITS):0]    last_len;
  logic                             out_ready;
  logic [DATA_OUT_BITS-1:0]         data_out;
  logic                             out_valid;
  logic                             in_ready;
  // ------------------------------------------------------------
  // Instantiate DUT
  // ------------------------------------------------------------
  sponge #(
    .LANE(LANE), 
    .LANES(LANES), 
    .STATE_W(STATE_W),
    .STEP_RND(STEP_RND), 
    .CAPACITY(CAPACITY),
    .DATA_IN_BITS(DATA_IN_BITS), 
    .DATA_OUT_BITS(DATA_OUT_BITS)
  ) dut (
    .clk, 
    .rst,
    .data_in, 
    .in_valid, 
    .in_last, 
    .last_len,
    .out_ready,
    .data_out, 
    .out_valid, 
    .in_ready
  );

  // ------------------------------------------------------------
  // Clock / Reset
  // ------------------------------------------------------------
  initial clk = 0;
  always #5 clk = ~clk; // 100 MHz

  initial begin
    rst = 1;
    repeat (5) @(posedge clk);
    rst = 0;
  end

  // ------------------------------------------------------------
  // Utility tasks
  // ------------------------------------------------------------
  task automatic send_block(input [DATA_IN_BITS-1:0] din,
                            input bit last = 0,
                            input int llen = DATA_IN_BITS);
    begin
      @(posedge clk);
      while (!in_ready) @(posedge clk);
      data_in  <= din;
      in_valid <= 1;
      in_last  <= last;
      last_len <= llen;
      @(posedge clk);
      data_in  <= '0;
      in_valid <= 0;
      in_last  <= 0;
      last_len <= 0;
    end
  endtask

  task automatic collect_digest(output logic [DIGEST_BITS-1:0] digest);
    int word_cnt = DIGEST_BITS / DATA_OUT_BITS;
    int idx = 0;

    out_ready = 1;   
    digest    = '0;

    for (int i=0; i<word_cnt; i++) begin
        @(posedge clk iff dut.out_valid);
        digest[idx*DATA_OUT_BITS +: DATA_OUT_BITS] <= dut.data_out;
        idx++;
    end

    $display("Digest = %h", digest);
  endtask


  // ------------------------------------------------------------
  // Case A: Exact-fit last block
  // ------------------------------------------------------------
  initial begin : caseA_exact_fit
    wait (!rst);
    $display("=== Case A: Exact-fit last block ===");
    // Suppose RATE=1088 (SHAKE256), DATA_IN_BITS=64
    // Create message length exactly multiple of RATE
    int blocks = RATE / DATA_IN_BITS; // number of full inputs
    for (int i=0; i<blocks-1; i++) begin
      send_block(64'hAAAA_BBBB_CCCC_DDDD, 0, DATA_IN_BITS);
    end
    // last block, fills exactly
    send_block(64'h1111_2222_3333_4444, 1, DATA_IN_BITS);

    // Assert FSM flow: should see permute_mode=01 then PAD_DATA then permute->squeeze
    // (Simplified, check keccak_en pulses twice)
    assert property (@(posedge clk) disable iff(rst)
        dut.state==dut.PAD_DATA |-> dut.keccak_en==1'b1)
    else $error("PAD_DATA must assert keccak_en for exact-fit");

    // Collect digest
    logic [DIGEST_BITS-1:0] digest;
    collect_digest(digest);
  end

  // ------------------------------------------------------------
  // Case B: Last-not-full
  // ------------------------------------------------------------
  initial begin : caseB_not_full
    wait (!rst);
    #2000; // wait after case A
    $display("=== Case B: Last-not-full block ===");
    // Feed one incomplete block
    send_block(64'hDEAD_BEEF_CAFE_F00D, 1, 16); // only 16 bits valid
    // Expect PAD_DATA with padded_safe used
    assert property (@(posedge clk) disable iff(rst)
        dut.state==dut.PAD_DATA |-> dut.keccak_en==1'b1)
      else $error("PAD_DATA must start permutation when last-not-full");

    // Collect digest
    logic [DIGEST_BITS-1:0] digest;
    collect_digest(digest);
  end

  // ------------------------------------------------------------
  // Case C: Multi-permute (long message)
  // ------------------------------------------------------------
  initial begin : caseC_long_message
    wait (!rst);
    #4000;
    $display("=== Case C: Multi-permute ===");
    // Feed >RATE bits, require multiple permutations
    int total_blocks = (2*RATE) / DATA_IN_BITS;
    for (int i=0; i<total_blocks; i++) begin
      send_block(i, (i==total_blocks-1), DATA_IN_BITS);
    end
    // Expect multiple keccak_en pulses
    assert property (@(posedge clk) disable iff(rst)
        dut.keccak_en |-> ##[1:$] dut.keccak_en)
    else $warning("Expected multiple keccak_en pulses for long message");

    // Collect digest
    logic [DIGEST_BITS-1:0] digest;
    collect_digest(digest);
  end

  // ------------------------------------------------------------
  // Case D: Squeeze with backpressure
  // ------------------------------------------------------------
  initial begin : caseD_backpressure
    wait (!rst);
    #6000;
    $display("=== Case D: Squeeze with backpressure ===");
    fork
      begin // producer: simple 1-block message
        send_block(64'h1234_5678_9ABC_DEF0, 1, DATA_IN_BITS);
      end
      begin // consumer: toggle out_ready
        forever begin
          @(posedge clk);
          out_ready <= $urandom_range(0,1);
        end
      end
    join_none

    // Assert: if out_valid && !out_ready then data_out must hold
    logic [DATA_OUT_BITS-1:0] prev_data;
    always @(posedge clk) begin
      if (out_valid && !out_ready) begin
        prev_data <= data_out;
      end
      if (out_valid && !out_ready) begin
        assert (data_out == prev_data)
          else $error("data_out changed while backpressured");
      end
    end
  end

endmodule
