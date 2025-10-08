`timescale 1ps/1ps

module ExpandA_tb;
    //localparam for ML-DSA87
    localparam K = 8;
    localparam L = 7;
    //raw data RAM localparam
    localparam WORD_WIDTH = 64;
    localparam TOTAL_WORD = 4096;
    localparam DATA_ADDR_WIDTH = $clog2(TOTAL_WORD);
    localparam RHO_BASE_OFFSET = 0;          //seed rho for expandA
    //NTT data RAM localparam
    localparam COEFF_WIDTH = 24;  // coefficient width is log2(q) = 23-bit ~ 24-bits for align word
    localparam COEFF_PER_WORD = 4;
    localparam WORD_COEFF = COEFF_WIDTH * COEFF_PER_WORD;
    localparam TOTAL_COEFF = 4096;
    localparam NTT_ADDR_WIDTH = $clog2(TOTAL_COEFF);
    localparam MATRIX_A_BASE_OFFSET = 0,     //matrixA 
    //SHAKE localparam
    localparam DATA_IN_BITS = WORD_WIDTH; //should divisible by 8
    localparam DATA_OUT_BITS = WORD_WIDTH;//should divisible by 8

    //DUT signals
    logic                           clk, rst, start, done;
    logic [DATA_IN_BITS-1 : 0]      rho;    
    logic                           we_matA;    //need K * L * N = 14336 word
    logic [NTT_ADDR_WIDTH-1:0]      addr_matA;  //offset(k,l,n) = k*(L*N) + l*N + n
    logic [WORD_COEFF-1:0]          din_matA;

    // shake128 instance
    logic                           absorb_next_poly;
    logic [DATA_IN_BITS-1:0]        shake_data_in;
    logic                           in_valid;
    logic                           in_last;
    logic [$clog2(DATA_IN_BITS):0]  last_len;
    logic                           cache_rst;
    logic                           cache_rd;
    logic                           cache_wr;
    logic                           out_ready;
    logic [DATA_OUT_BITS-1:0]       shake_data_out;
    logic                           out_valid;
    logic                           in_ready;

    ExpandA #(
        .K(K),
        .L(L)
    ) expandA (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done), 
        .we_matA(we_matA), 
        .addr_matA(addr_matA), 
        .din_matA(din_matA),
        // shake128 instance
        .absorb_next_poly(absorb_next_poly),
        .shake_data_in(shake_data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(last_len),
        .cache_rd(cache_rd),
        .cache_wr(cache_wr),
        .out_ready(out_ready),
        .shake_data_out(shake_data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );

    sponge #(
        .CAPACITY(256),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) shake128 (
        .clk(clk),
        .rst(rst | absorb_next_poly),
        .data_in(shake_data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(last_len),
        .cache_rst(cache_rst),
        .cache_rd(cache_rd),
        .cache_wr(cache_wr),
        .out_ready(out_ready),
        .data_out(shake_data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );

    //dp_ram_true signals
    logic [WORD_COEFF-1:0]    dout_a = 0, dout_b = 0;

    dp_ram_true #(
        .ADDR_WIDTH(NTT_ADDR_WIDTH),
        .DATA_WIDTH(WORD_COEFF)
    ) matA (
        .clk(clk),
        .we_a(we_matA),
        .addr_a(addr_matA),
        .din_a(din_matA),
        .dout_a(dout_a),
        .we_b(0),
        .addr_b(0),
        .din_b(0),
        .dout_b(dout_b)
    );

    task automatic send_block(input [DATA_IN_BITS-1:0] din);
        begin
            @(posedge clk);
            rho  <= din;
        end
    endtask

    // Test instance
    integer i, j, cnt = 0, fd;

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        rst = 1; 
        cache_rst = 1;
        repeat (5) @(posedge clk);
        rst = 0;
        cache_rst = 0;
    end

    initial begin
        //wait for reset to complete
        wait (!rst);
        repeat (5) @(posedge clk);

        //pulse start and push data in
        @(posedge clk);
        start = 1;
        // =================== WRITE YOUR TEST logic ===================
        @(posedge clk);
        start = 0; 
        rho = 64'h1234567890abcdef; //first block
        
        send_block(64'h1234567890abcdef);
        send_block(64'h1234567890abcdef);
        send_block(64'h1234567890abcdef);

        //wait for operation to complete
        wait(done);
        @(posedge clk);
        fd = $fopen("G:/Y4S1/DATN/PQC_Dilithium/fpga/dilithium_test_bench/mem_dump.txt", "w");
        if (fd == 0) begin
            $display("Cannot open file mem_dump.txt");
            $finish;
        end

        $fdisplay(fd, "ExpandA output:");

        for (i = 0; i < (1<<matA.ADDR_WIDTH); i = i + 1) begin
            for(j = 0; j < COEFF_PER_WORD; j = j+1) begin
                $fdisplay(fd, "%0d: %0d", cnt, $signed(matA.mem[i][j*COEFF_WIDTH+:COEFF_WIDTH]));
                cnt = cnt + 1;
            end
        end
        $fclose(fd);
        $display("Simulation done");
        #50 $finish;
    end
endmodule