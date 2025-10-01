`timescale 1ps/1ps

module ExpandA_tb;
    //Parameters match DUT
    localparam SEED_SIZE = 32 * 8;
    localparam REJ_NTT_POLY_SEED = 34 * 8;
    localparam K = 8;
    localparam L = 7;
    localparam N = 256;                              
    localparam COEFF_WIDTH = 24; 
    localparam int WORD_LEN = COEFF_WIDTH * 4;         
    localparam DATA_IN_BITS = 64;        
    localparam DATA_OUT_BITS = 64;
    localparam ADDR_POLY_WIDTH = $clog2(K*L*N*COEFF_WIDTH/WORD_LEN);
    localparam int COEFF_PER_WORD = WORD_LEN / COEFF_WIDTH;

    //DUT signals
    logic                               clk, rst, start, done;
    logic [SEED_SIZE-1 : 0]             rho;    

    //RejNTTPoly instance
    logic [3:0]                         k, l;
    logic                               RejNTTPoly_start;  //pulse 1 cycle        
    logic [REJ_NTT_POLY_SEED-1 : 0]     RejNTTPoly_rho;    //34 bytes         
    logic                               RejNTTPoly_done;   //sampling done, pulse 1 cycle 
    logic          we_matA;                         //need K * L * N = 14336 word
    logic [ADDR_POLY_WIDTH-1:0]         addr_matA;  //offset(k,l,n) = k*(L*N) + l*N + n
    logic [WORD_LEN-1:0]                din_matA;

    // shake128 instance
    // logic                               absorb_next_poly;
    logic [DATA_IN_BITS-1:0]            shake_data_in;
    logic                               in_valid;
    logic                               in_last;
    logic [$clog2(DATA_IN_BITS):0]      last_len;
    logic                               out_ready;
    logic [DATA_OUT_BITS-1:0]           shake_data_out;
    logic                               out_valid;
    logic                               in_ready;

    // Instantiate the DUT
    ExpandA #(
        .K(K),
        .L(L),
        .N(N),
        .COEFF_WIDTH(COEFF_WIDTH),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) expandA (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done),
        .k(k), .l(l),
        .RejNTTPoly_start(RejNTTPoly_start),
        .RejNTTPoly_rho(RejNTTPoly_rho),
        .RejNTTPoly_done(RejNTTPoly_done)
    );

    RejNTTPoly #(
        .N(N),
        .COEFF_WIDTH(COEFF_WIDTH), // coefficient width is log2(q) = 23-bit ~ 24-bits for align word
        .DATA_IN_BITS(DATA_IN_BITS), //should divisible by 8
        .DATA_OUT_BITS(DATA_OUT_BITS) //should divisible by 8
    ) rejNTTPoly (
        .clk(clk),
        .rst(rst),
        .start(RejNTTPoly_start),
        .rho(RejNTTPoly_rho),
        .done(RejNTTPoly_done),
        .l(l), .k(k), 
        .we_matA(we_matA), 
        .addr_matA(addr_matA), 
        .din_matA(din_matA),
        // shake128 instance
        // .absorb_next_poly(absorb_next_poly),
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
        .CAPACITY(256),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) shake128 (
        .clk(clk),
        .rst(rst | RejNTTPoly_start),
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

    // Test instance
    integer i, j, cnt = 0, fd;

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        rst = 1; 
        repeat (5) @(posedge clk);
        rst = 0;
    end

    initial begin
        //wait for reset to complete
        wait (!rst);
        repeat (5) @(posedge clk);

        //pulse start and push data in
        @(posedge clk);
        start = 1;
        // =================== WRITE YOUR TEST logic ===================
        rho = 256'h1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef;
        @(posedge clk);
        start = 0;

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