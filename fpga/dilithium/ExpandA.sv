`timescale 1ns / 1ps
// Algorithm 32: FIPS 204 page 38, slide 48
// Samples a {k x l} matrix A in T_q from a seed rho
// Input: rho is a 32-byte seed
// Output: Matrix A in T_q^{k x l}
//         Each entry is a polynomial (list of 256 coefficients mod q)

module ExpandA #( 
    parameter int SEED_SIZE = 32 * 8,  // SHALL NOT MODIFY
    parameter int REJ_NTT_POLY_SEED = 34 * 8, //SHALL NOT MODIFY
    parameter int K = 8,              // number of rows
    parameter int L = 7,              // number of columns
    parameter int N = 256,            // number of coefficients per polynomial
    parameter int COEFF_WIDTH = 24,   // coefficient width is log2(q) = 23-bit ~ 24-bits for align
    parameter int DATA_IN_BITS = 64,  //should divisible by 8
    parameter int DATA_OUT_BITS = 64  //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [SEED_SIZE - 1 : 0]         rho,        //32 bytes         
    output reg                              done,       //pulse 1 cycle     

    //RejNTTPoly instance
    output reg  [3:0]                       k, l,
    output reg                              RejNTTPoly_start,  //pulse 1 cycle        
    output reg  [REJ_NTT_POLY_SEED-1 : 0]   RejNTTPoly_rho,    //34 bytes         
    input  wire                             RejNTTPoly_done   //sampling done, pulse 1 cycle  
);
    reg active;
    always @(posedge clk) begin
        if (rst) begin
            active <= 0;
            k <= 0;
            l <= 0;
            RejNTTPoly_start <= 0;
            RejNTTPoly_rho <= 0;
            done <= 0;
        end else if (start) begin
            active <= 1;
            k <= 0;
            l <= 0;
            RejNTTPoly_start <= 1;
            RejNTTPoly_rho <= {{8'b00000000}, {8'b00000000}, rho};
            done <= 0;
        end else if (active) begin
            if (RejNTTPoly_done) begin
                if (l >= L-1) begin
                    if (k >= K-1) begin
                        done <= 1;
                        active <= 0;
                    end else begin
                        k <= k + 1;
                        l <= 0;
                        RejNTTPoly_start <= 1;
                        RejNTTPoly_rho <= { 8'((k+1)), 8'd0, rho };
                    end
                end else begin
                    k <= k;
                    l <= l + 1;
                    RejNTTPoly_start <= 1;
                    RejNTTPoly_rho <= { 8'(k), 8'((l+1)), rho };
                end 
            end else begin
                RejNTTPoly_start <= 0;
                done <= 0;
            end
        end else begin
            done <= 0;
        end
    end
endmodule