`timescale 1ps/1ps

module ExpandMask_tb;
    //parameters for DUT
    localparam int SEED_SIZE = 64 * 8;
    localparam int RHO_PRIME = 66 * 8;
    localparam int L = 7;
    localparam int N = 256;
    localparam int GAMMA1 = 19; 
    localparam integer gamma1 = (1 << GAMMA1);
    localparam int COEFF_WIDTH = GAMMA1 + 1; //step 1 of Algorithm 34: c = 1 + bitlen(gamma1-1)
    //localparam for shake256 instance
    localparam int DATA_IN_BITS = 64;
    localparam int DATA_OUT_BITS = 64;
    //parameter for BRAM cache instance
    localparam int ADDR_WIDTH = $clog2(1088 / DATA_OUT_BITS);
    localparam int DATA_WIDTH = DATA_OUT_BITS;
    localparam int ADDR_POLY_WIDTH = $clog2(L*N*COEFF_WIDTH/WORD_LEN)
    localparam int COEFF_PER_WORD = WORD_LEN / COEFF_WIDTH;

    //DUT signals
    logic                           clk, rst, start, done;
    logic [SEED_SIZE-1:0]           rho;
    logic [15 : 0]                  mu;
    
    logic                           we_vector_y;
    logic [ADDR_POLY_WIDTH -1:0]    addr_vector_y;
    logic [WORD_LEN-1:0]            din_vector_y;

    //shake256 instance
    logic                               absorb_next_poly; //shake force reset
    logic  [DATA_IN_BITS-1:0]           shake_data_in;
    logic                               in_valid;
    logic                               in_last;
    logic [$clog2(DATA_IN_BITS) :0]    last_len;
    logic                               out_ready;
    logic [DATA_OUT_BITS-1:0]           shake_data_out;
    logic                               out_valid;
    logic                               in_ready;

    //Instance the DUT
    ExpandMask #(
        .L(L),
        .N(N),
        .GAMMA1(GAMMA1),
        .COEFF_BIT_LEN(COEFF_BIT_LEN),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS),
        .ADDR_WIDTH(ADDR_WIDTH),
        .DATA_WIDTH(DATA_WIDTH),
        .ADDR_POLY_WIDTH(ADDR_POLY_WIDTH)
    ) dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .mu(mu),
        .done(done),
        //vector y signals
        .we_vector_y(we_vector_y),
        .addr_vector_y(addr_vector_y),
        .din_vector_y(din_vector_y),
        //shake256 instance
        .absorb_next_poly(absorb_next_poly),
        .shake_data_in(shake_data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(last_len),
        .out_ready(out_ready),
        .shake_data_out(shake_data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );

    sponge #(
        .CAPACITY(512),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) shake256 (
        .clk(clk),
        .rst(rst | absorb_next_poly),
        .data_in(shake_data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(last_len),
        .out_ready(out_ready),
        .data_out(shake_data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );

    //dp_ram_true signals
    logic [WORD_LEN-1:0]    dout_a = 0, dout_b = 0;

    dp_ram_true #(
        .ADDR_WIDTH(ADDR_POLY_WIDTH),
        .DATA_WIDTH(WORD_LEN)
    ) vector_y (
        .clk(clk),
        .we_a(we_vector_y),
        .addr_a(addr_vector_y),
        .din_a(din_vector_y),
        .dout_a(dout_a),
        .we_b(0),
        .addr_b(0),
        .din_b(0),
        .dout_b(dout_b)
    );

    integer i, j, cnt = 0, fd;

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        rst = 1;
        repeat (5) @(posedge clk);
        rst = 0;
    end

    initial begin
        wait(!rst);
        repeat (5) @(posedge clk);

        @(posedge clk);
        start = 1;
    // =================== WRITE YOUR TEST logic ===================
        rho = 512'h1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef;
        mu = 16'h0001;
        @(posedge clk);
        start = 0;

        wait(done);
        @(posedge clk);
        fd = $fopen("G:/Y4S1/DATN/PQC_Dilithium/fpga/dilithium_test_bench/mem_dump.txt", "w");
        if (fd == 0) begin
            $display("Cannot open file mem_dump.txt");
            $finish;
        end

        // $fdisplay(fd, "--------------------------------------");
        // $fdisplay(fd, "  Dump memory: %0d words", (1<<vector_y.ADDR_WIDTH));
        // $fdisplay(fd, "  Format: index | decimal | hex");
        // $fdisplay(fd, "--------------------------------------");
        $fdisplay(fd, "ExpandMask output:");
        for (i = 0; i < (1<<vector_y.ADDR_WIDTH); i = i + 1) begin
            // $fdisplay(fd, "%4d : %10d | 0x%0h", i, $signed(vector_y.mem[i]), vector_y.mem[i]);
            for(j = 0; j < COEFF_PER_WORD; j = j+1) begin
                $fdisplay(fd, "%0d: %0d", cnt, $signed(vector_s.mem[i][j*COEFF_WIDTH+:COEFF_WIDTH]));
                cnt = cnt + 1;
            end
        end
        $fclose(fd);
        $display("Simulation done");
        #50 $finish;
    end
endmodule