`timescale 1ns / 1ps
// This should be described as a state in the Dilithium specification only
// Algorithm 33: Sampling the secret vectors s1 and s2, FIPS 204 page 38, slide 48
// Samples vector s1 in R_q^l and s2 in R_q^k with coefficients in [-eta, eta]
// Input: rho is a 64-byte seed
// Output: Vector s1 and s2 of polynomials in R_q
//         Each entry is a polynomial (list of 256 coefficients mod q)

#define SEED_SIZE 64 * 8
#define REJ_BOUNDED_POLY 66 * 8

module ExpandS #( 
    parameter int K = 8,                // number of rows
    parameter int L = 7,                // number of columns
    parameter int N = 256,              // number of coefficients per polynomial
    parameter int ETA = 2,              // private key range in Dilithium
    parameter int COEFF_WIDTH = 4,      // coefficient width is log2(q) = 23-bit value + 1-bit valid = 24 bits
    parameter int DATA_IN_BITS = 64,    //should divisible by 8
    parameter int DATA_OUT_BITS = 64    //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [`SEED_SIZE - 1 : 0]        rho,        //64 bytes         
    output reg                              done,       //sampling done, pulse 1 cycle     
    output reg  [COEFF_WIDTH * N - 1 : 0]   s1[L],      //packed matrix s1 output
    output reg  [COEFF_WIDTH * N - 1 : 0]   s2[K]       //packed matrix s2 output
);
    reg  [3:0] cnt;
    // ------------------------------------------------------------
    // Signals for RejBoundedPoly s1 instance
    reg                              RejBoundedPoly_start;  //pulse 1 cycle        
    reg  [SEED_SIZE-1 : 0]           RejBoundedPoly_rho;    //64 bytes         
    wire                             RejBoundedPoly_done;   //sampling done, pulse 1 cycle     
    wire [COEFF_WIDTH * N - 1 : 0]   RejBoundedPoly_poly;   //packed polynomial output
    // ------------------------------------------------------------

    always @(posedge clk) begin
        if (rst) begin
            cnt <= 0;
            done <= 0;
            for (int i = 0; i < L; i = i + 1) begin
                s1[i] <= 0;
            end
            for (int i = 0; i < K; i = i + 1) begin
                s2[i] <= 0;
            end
        end else if (start) begin
            cnt <= 0;
            done <= 0;
            for (int i = 0; i < L; i = i + 1) s1[i] <= 0;
            for (int i = 0; i < K; i = i + 1) s2[i] <= 0;

            RejBoundedPoly_start <= 1;
            RejBoundedPoly_rho <= {rho, {8'b00000000}, {8'b00000000}};
        end else if (RejBoundedPoly_done) begin
            if (cnt < L) begin
                s1[cnt] <= RejBoundedPoly_poly;
                cnt <= cnt + 1;
                RejBoundedPoly_start <= 1;
                RejBoundedPoly_rho <= {rho, {8'b00000000}, {4'b0000, cnt + 1}};
            end else if (cnt < L + K) begin
                s2[cnt - L] <= RejBoundedPoly_poly;
                cnt <= cnt + 1;
                RejBoundedPoly_start <= 1;
                RejBoundedPoly_rho <= {rho, {8'b00000000}, {4'b0000, cnt + 1}};
            end else begin
                done <= 1;
            end
        end else begin
            RejBoundedPoly_start <= 0;
        end
    end

    RejBoundedPoly #( 
    .N(N),          // output are 256 coefficients from a polynomial
    .ETA(ETA),      // private key range in Dilithium
    .COEFF_WIDTH(COEFF_WIDTH), // coefficient width is log2(q) = 23-bit value + 1-bit valid = 24 bits
    .DATA_IN_BITS(DATA_IN_BITS), //should divisible by 8
    .DATA_OUT_BITS(DATA_OUT_BITS)  //should divisible by 8
    ) RejBoundedPoly_instance (
    .clk(clk),
    .rst(rst),
    .start(RejBoundedPoly_start),
    .rho(RejBoundedPoly_rho),
    .done(RejBoundedPoly_done),
    .poly(RejBoundedPoly_poly)
    );

endmodule