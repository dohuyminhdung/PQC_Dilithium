`timescale 1ps/1ps

module SampleInBall_tb;
    //Parameters match DUT       
    localparam int N = 256;
    localparam int COEFF_WIDTH = 24;         
    localparam int LAMBDA = 256;             
    localparam int TAU = 60;
    localparam int SEED_SIZE = LAMBDA/4*8;
    localparam int WORD_LEN = 96;
    //parameter for shake256 instance
    parameter int DATA_IN_BITS = 64;
    parameter int DATA_OUT_BITS = 64;
    //parameter for BRAM cache instance
    parameter int ADDR_POLY_WIDTH = $clog2(256*COEFF_WIDTH/WORD_LEN+1);
    localparam int COEFF_PER_WORD = WORD_LEN / COEFF_WIDTH;     

    //DUT signals
    logic                           clk, rst, start, done;
    logic [SEED_SIZE-1 : 0]         rho;
    logic                           we_poly_c;
    logic [ADDR_POLY_WIDTH-1:0]     addr_poly_c;  
    logic [WORD_LEN-1:0]            din_poly_c;
    //shake256 instance
    logic [DATA_IN_BITS-1:0]        shake_data_in;
    logic                           in_valid;
    logic                           in_last;
    logic [$clog2(DATA_IN_BITS):0]  last_len;
    logic                           out_ready;
    logic [DATA_OUT_BITS-1:0]       shake_data_out;
    logic                           out_valid;
    logic                           in_ready;

    // Instantiate the DUT
    SampleInBall #(
        .LAMBDA(LAMBDA),
        .TAU(TAU),
        .SEED_SIZE(SEED_SIZE),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS),
        .ADDR_POLY_WIDTH(ADDR_POLY_WIDTH)
    ) sample_in_ball (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done),
        .we_poly_c(we_poly_c),
        .addr_poly_c(addr_poly_c),  
        .din_poly_c(din_poly_c),
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
        .rst(rst),
        .data_in(shake_data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(last_len),
        .out_ready(out_ready),
        .data_out(shake_data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );

    logic [WORD_LEN-1:0] dout_a = 0, dout_b = 0;
    dp_ram_true #(
        .ADDR_WIDTH(ADDR_POLY_WIDTH),
        .DATA_WIDTH(WORD_LEN)
    ) poly_c (
        .clk(clk),
        .we_a(we_poly_c),
        .addr_a(addr_poly_c),
        .din_a(din_poly_c),
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
        //wait for reset to complete
        wait (!rst);
        repeat (5) @(posedge clk);

        //pulse start and push data in
        @(posedge clk);
        start = 1;
        // =================== WRITE YOUR TEST logic ===================
        rho = 512'h1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef_1234567890abcdef;
        @(posedge clk);
        start = 0;

        wait(done);
        @(posedge clk);
        fd = $fopen("G:/Y4S1/DATN/PQC_Dilithium/fpga/dilithium_test_bench/mem_dump.txt", "w");
        if (fd == 0) begin
            $display("Cannot open file mem_dump.txt");
            $finish;
        end

        $fdisplay(fd, "SampleInBall output:");
        for (i = 0; i < (1<<poly_c.ADDR_WIDTH); i = i + 1) begin
            for(j = 0; j < COEFF_PER_WORD; j = j+1) begin
                $fdisplay(fd, "%0d: %0d", cnt, $signed(poly_c.mem[i][j*COEFF_WIDTH+:COEFF_WIDTH]));
                cnt = cnt + 1;
            end
        end
        $fclose(fd);
        $display("Simulation done");
        #50 $finish;
    end
endmodule