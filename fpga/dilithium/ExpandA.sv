`timescale 1ns / 1ps
// This should be described as a state in the Dilithium specification only
// Algorithm 32: FIPS 204 page 38, slide 48
// Samples a {k x l} matrix A in T_q from a seed rho
// Input: rho is a 32-byte seed
// Output: Matrix A in T_q^{k x l}
//         Each entry is a polynomial (list of 256 coefficients mod q)

#define SEED_SIZE 32 * 8
#define REJ_NTT_POLY 34 * 8

module ExpandA #( 
    parameter int K = 8,              // number of rows
    parameter int L = 7,              // number of columns
    parameter int N = 256,            // number of coefficients per polynomial
    parameter int COEFF_WIDTH = 24,   // coefficient width is log2(q) = 23-bit value + 1-bit valid = 24 bits
    parameter int DATA_IN_BITS = 64,  //should divisible by 8
    parameter int DATA_OUT_BITS = 64  //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [`SEED_SIZE - 1 : 0]        rho,        //32 bytes         
    output reg                              done,       //sampling done, pulse 1 cycle     
    output reg  [COEFF_WIDTH * N - 1 : 0]   matA[K][L]  //packed matrix A output
);
    reg  [3:0] s, r;
    // ------------------------------------------------------------
    // Signals for RejNTTPoly instance
    reg                              RejNTTPoly_start;  //pulse 1 cycle        
    reg  [SEED_SIZE-1 : 0]           RejNTTPoly_rho;    //34 bytes         
    wire                             RejNTTPoly_done;   //sampling done, pulse 1 cycle     
    wire [COEFF_WIDTH * N - 1 : 0]   RejNTTPoly_poly;   //packed polynomial output
    // ------------------------------------------------------------

    always @(posedge clk) begin
        if (rst) begin
            r <= 0;
            s <= 0;
            done <= 0;
            for (int i = 0; i < K; i = i + 1) begin
                for (int j = 0; j < L; j = j + 1) begin
                    matA[i][j] <= 0;
                end
            end
        end else if (start) begin
            r <= 0;
            s <= 0;
            done <= 0;
            for (int i = 0; i < K; i = i + 1) begin
                for (int j = 0; j < L; j = j + 1) begin
                    matA[i][j] <= 0;
                end
            end
            
            RejNTTPoly_start <= 1;
            RejNTTPoly_rho <= {rho, {8'b00000000}, {8'b00000000}};
        end else if (RejNTTPoly_done) begin
            matA[r][s] <= RejNTTPoly_poly;
            if (s >= L-1) begin
                if (r >= K-1) begin
                    done <= 1;
                end else begin
                    r <= r + 1;
                    s <= 0;
                    RejNTTPoly_start <= 1;
                    RejNTTPoly_rho <= {rho, {8'b00000000}, {4'b0000, r+1}};
                end
            end else begin
                s <= s + 1;
                RejNTTPoly_start <= 1;
                RejNTTPoly_rho <= {rho, {4'b0000, s+1}, {4'b0000, r}};
            end 
        end else begin
            RejNTTPoly_start <= 0;
        end
    end

    RejNTTPoly #( 
    .N(N),          // output are 256 coefficients from a polynomial
    .COEFF_WIDTH(COEFF_WIDTH), // coefficient width is log2(q) = 23-bit value + 1-bit valid = 24 bits
    .DATA_IN_BITS(DATA_IN_BITS), //should divisible by 8
    .DATA_OUT_BITS(DATA_OUT_BITS)  //should divisible by 8
    ) RejNTTPoly_instance (
    .clk(clk),
    .rst(rst),
    .start(RejNTTPoly_start),
    .rho(RejNTTPoly_rho),
    .done(RejNTTPoly_done),
    .poly(RejNTTPoly_poly)
    );
endmodule