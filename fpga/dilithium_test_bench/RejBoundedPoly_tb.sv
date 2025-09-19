`timescale 1ns/1ps

//SHALL NOT MODIFY THESE MACRO
`define SEED_SIZE 528 //66*8 

module RejBoundedPoly_tb;
    //Parameters match DUT
    localparam N = 256;                  
    localparam ETA = 2;               
    localparam COEFF_WIDTH = 2;          
    localparam DATA_IN_BITS = 64;        
    localparam DATA_OUT_BITS = 64;
    
    //DUT signals
    logic                             clk, rst, start, done;
    logic [`SEED_SIZE-1 : 0]          rho;
    logic [COEFF_WIDTH * N - 1 : 0]   poly_pack;

    // Instantiate the DUT
    RejBoundedPoly #(
        .N(N),
        .ETA(ETA),
        .COEFF_WIDTH(COEFF_WIDTH),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .rho(rho),
        .done(done),
        .poly_pack(poly_pack)
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
        //2 final bytes should only range from 0 to 15
        rho = 528'h
                1234567890abcdef_1234567890abcdef_
                1234567890abcdef_1234567890abcdef_
                1234567890abcdef_1234567890abcdef_
                1234567890abcdef_1234567890abcdef_aaaa;
        @(posedge clk);
        start = 0;

        //wait for operation to complete
        wait(done);
        @(posedge clk);
        $display("[%0t] Done asserted! poly_pack = 0x%0h", $time, poly_pack);
        #50 $finish;
    end
endmodule