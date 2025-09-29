`timescale 1ps/1ps

module ExpandS_tb;
    localparam int SEED_SIZE = 64*8;             //SHALL NOT MODIFY 
    localparam int REJ_BOUNDED_POLY_SEED = 66*8; //SHALL NOT MODIFY
    localparam int WORD_LEN = 96;  
    localparam int K = 8;                // number of rows
    localparam int L = 7;                // number of columns             
    localparam int N   = 256;            //logic 256 coefficients from a polynomial   
    localparam int ETA = 2;              //private key range in Dilithium
    localparam int COEFF_WIDTH = 24;      //coefficient is guarantee in range [-eta, eta] = [-2, 2]
    //localparam for shake256 instance
    localparam int DATA_IN_BITS = 64;
    localparam int DATA_OUT_BITS = 64;
    //localparam for BRAM cache instance
    localparam int ADDR_WIDTH = $clog2(1088 / DATA_OUT_BITS);
    localparam int DATA_WIDTH = DATA_OUT_BITS;
    localparam int ADDR_POLY_WIDTH = $clog2((L+K)*N*COEFF_WIDTH/WORD_LEN);
    localparam int COEFF_PER_WORD = WORD_LEN / COEFF_WIDTH;
    
    //DUT signals
    logic                             clk;
    logic                             rst;
    logic                             start;      //pulse 1 cycle        
    logic [SEED_SIZE-1 : 0]           rho;        //64 bytes         
    logic                             done;       //sampling done, pulse 1 cycle     
    
    logic we_vector_s;
    logic [ADDR_POLY_WIDTH -1:0]  addr_vector_s;  //(L+K)*N/2 = 15 * 256 / 2 = 1920 words (log2(1920) = 11)
    logic [WORD_LEN-1:0]                    din_vector_s;   
    
    //shake256 instance
    logic                              absorb_next_poly; //shake force reset
    logic  [DATA_IN_BITS-1:0]          shake_data_in;
    logic                              in_valid;
    logic                              in_last;
    logic [$clog2(DATA_IN_BITS) : 0]  last_len;
    logic                              out_ready;
    logic [DATA_OUT_BITS-1:0]         shake_data_out;
    logic                             out_valid;
    logic                             in_ready;

    // Instantiate the DUT
    ExpandS #(
        .SEED_SIZE(SEED_SIZE),
        .REJ_BOUNDED_POLY_SEED(REJ_BOUNDED_POLY_SEED),
        .WORD_LEN(WORD_LEN),
        .K(K),
        .L(L),
        .N(N),
        .ETA(ETA),
        .COEFF_WIDTH(COEFF_WIDTH),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS),
        .ADDR_WIDTH(ADDR_WIDTH),
        .DATA_WIDTH(DATA_WIDTH)
    ) expandS (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done),
        .we_vector_s(we_vector_s),
        .addr_vector_s(addr_vector_s),
        .din_vector_s(din_vector_s),
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
    logic [WORD_LEN-1:0]                    dout_a = 0, dout_b = 0;

    dp_ram_true #(
        .ADDR_WIDTH(ADDR_POLY_WIDTH),
        .DATA_WIDTH(WORD_LEN)
    ) vector_s (
        .clk(clk),
        .we_a(we_vector_s),
        .addr_a(addr_vector_s),
        .din_a(din_vector_s),
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
        wait (!rst);
        repeat (5) @(posedge clk);

        @(posedge clk);
        start = 1;
        // =================== WRITE YOUR TEST INPUT HERE ===================
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

        $fdisplay(fd, "ExpandS output:");
        for (i = 0; i < (1<<vector_s.ADDR_WIDTH); i = i + 1) begin
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