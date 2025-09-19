`timescale 1ps/1ps

#define SEED_SIZE 256 // 32*8

module ExpandA_tb;
    //Parameters match DUT
    localparam K = 8;
    localparam L = 7;
    localparam N = 256;                              
    localparam COEFF_WIDTH = 24;          
    localparam DATA_IN_BITS = 64;        
    localparam DATA_OUT_BITS = 64;
    
    //DUT signals
    logic                             clk, rst, start, done;
    logic [`SEED_SIZE-1 : 0]          rho;
    logic [COEFF_WIDTH * N - 1 : 0]   matA[K][L];

    // Instantiate the DUT
    ExpandA #(
        .K(K),
        .L(L),
        .N(N),
        .COEFF_WIDTH(COEFF_WIDTH),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done),
        .matA(matA)
    );

    // Test instance
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
        // =================== WRITE YOUR TEST INPUT HERE ===================
        rho = 256'h
                1234567890abcdef_1234567890abcdef_
                1234567890abcdef_1234567890abcdef;
        @(posedge clk);
        start = 0;

        //wait for operation to complete
        wait(done);
        @(posedge clk);
        for (i = 0; i < K; i++) begin
            $write("Row %0d : ", i);
            for (j = 0; j < L; j++) begin
                $write("0x%0h ", matA[i][j]);
            end
            $write("\n");
        end
        #50 $finish;
    end
endmodule