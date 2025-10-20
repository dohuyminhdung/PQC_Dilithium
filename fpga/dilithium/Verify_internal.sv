`timescale 1ns / 1ps
// Reference: Algorithm 8: Signature verification, FIPS 204 page 27, slide 37
// Internal function to verify a signature sigma for a formatted message M'
// Input:  Public key pk (length of 32 + 32*k*(bitlen(q-1)-d) bytes), formatted message M_, 
//         signature sigma (length of lambda/4 + 32*l*(1+bitlen(gamma1-1)) + omega + k)
// Output: True if the signature is valid, False otherwise
module Sign_internal #(
    //ML-DSA87 parameters: FIPS 204, page 15, slide 25
    parameter int Q = 8380417,
    parameter int N = 256,              //number of coeff in a polynomial
    parameter int D = 13,               //number of drop bits from t
    parameter int TAU = 60,             //number of [-1, 1] in polynomial c 
    parameter int LAMBDA = 256,          //collision strength of challenge c~
    parameter int GAMMA1 = 19,          //2^GAMMA1 = coeff range of vector y
    parameter int gamma1 = 1 << GAMMA1,
    parameter int GAMMA2 = (Q-1)/32,    //low-order rounding range
    parameter int K = 8,                //number of rows of matrix A
    parameter int L = 7,                //number of cols of matrix A
    parameter int ETA = 2,              //the bound for coefficients of secret vectors s1, s2
    parameter int BETA = TAU * ETA,     //valid check constant in step 23
    parameter int OMEGA = 75,           //max number of 1's in the hint vector h 
    // parameter int KAPPA_BOUND = 814*L,  //Appendix C - Loop Bounds for ML-DSA.Sign_internal
    //                                     //FIPS204, page 52, slide 62
    //raw data RAM parameters
    parameter int WORD_WIDTH = 64,      //FIXED, SHALL NOT MODIFY
    parameter int TOTAL_WORD = 4096,
    parameter int DATA_ADDR_WIDTH = $clog2(TOTAL_WORD),

    parameter int RHO_BASE_OFFSET = 0,          //seed rho for expandA
    parameter int RHO_END_OFFSET = RHO_BASE_OFFSET + (32*8/WORD_WIDTH),

    parameter int RHO_PRIME_BASE_OFFSET = 0,    //seed rho' for expandS
    parameter int RHO_PRIME_END_OFFSET = RHO_PRIME_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int PUBLIC_KEY_SIZE = (32 + 32 * K * ($clog2(Q-1) - D)) * 8, //2592 bytes for ML-DSA87
    parameter int PUBLIC_KEY_END_OFFSET = PUBLIC_KEY_BASE_OFFSET + (PUBLIC_KEY_SIZE/WORD_WIDTH),

    parameter int SECRET_KEY_BASE_OFFSET = 0,   //rho, K, tr, s1.encode, s2.encode, t0
    parameter int SECRET_KEY_SIZE = (32 + 32 + 64 + 32 * ((K+L) * $clog2(ETA*2+1) + D * K)), //4896 bytes for ML-DSA87
    parameter int SECRET_KEY_END_OFFSET = SECRET_KEY_BASE_OFFSET + SECRET_KEY_SIZE,  

    parameter int SIGNATURE_BASE_OFFSET = 0,    //c~, z mod_pm q, h
    parameter int SIGNATURE_SIZE = (LAMBDA/4 + L * 32 * (1 + $clog2(gamma1-1)) + OMEGA + K) * 8,
    parameter int SIGNATURE_END_OFFSET = SIGNATURE_BASE_OFFSET + SIGNATURE_SIZE,

    parameter int K_BASE_OFFSET = SECRET_KEY_BASE_OFFSET + (32*8/WORD_WIDTH),   //K is use for signing
    parameter int K_END_OFFSET = K_BASE_OFFSET + (32*8/WORD_WIDTH),

    parameter int TR_BASE_OFFSET = K_BASE_OFFSET + (32*8/WORD_WIDTH),            //tr is use for signing
    parameter int TR_END_OFFSET  = TR_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int MESSAGE_BASE_OFFSET = 0,  //message to sign, M' = BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ M
                                            // TR || BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ M
                                            // Let software handle concating ctx with message: TR || M'

    parameter int MU_BASE_OFFSET = 0,       //seed after hashing message in step 6
    parameter int MU_END_OFFSET = MU_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int RND_BASE_OFFSET = 0,      //rnd seed for absorbing in step 7
    parameter int RND_END_OFFSET = RND_BASE_OFFSET + (32*8/WORD_WIDTH), 

    parameter int RHO_PP_BASE_OFFSET = 0,   //seed rho'' for expandMask
    parameter int RHO_PP_END_OFFSET = RHO_PP_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int CHALLENGE_BASE_OFFSET = SIGNATURE_BASE_OFFSET,    //seed rho for SampleInBall
    parameter int CHALLENGE_END_OFFSET = CHALLENGE_BASE_OFFSET + (LAMBDA/4*8/WORD_WIDTH), 

    //NTT data RAM parameters
    parameter int COEFF_WIDTH = 24,         //FIXED, SHALL NOT MODIFY
    parameter int COEFF_PER_WORD = 4,       //FIXED, SHALL NOT MODIFY
    parameter int WORD_COEFF = COEFF_WIDTH * COEFF_PER_WORD,
    parameter int TOTAL_COEFF = 4096,
    parameter int NTT_ADDR_WIDTH = $clog2(TOTAL_COEFF),

    parameter int MATRIX_A_BASE_OFFSET = 0,     //matrixA           from expandA
    parameter int MATRIX_A_TOTAL_WORD = (K*L*N/COEFF_PER_WORD), 
    parameter int MATRIX_A_END_OFFSET = MATRIX_A_BASE_OFFSET + MATRIX_A_TOTAL_WORD,

    parameter int VECTOR_S_BASE_OFFSET = 0,     //vector s1, s2     from expandS
    parameter int VECTOR_S_TOTAL_WORD = (K+L)*N/COEFF_PER_WORD,
    parameter int VECTOR_S_END_OFFSET = VECTOR_S_BASE_OFFSET + VECTOR_S_TOTAL_WORD,
    parameter int VECTOR_S1_BASE_OFFSET = VECTOR_S_BASE_OFFSET,
    parameter int VECTOR_S2_BASE_OFFSET = VECTOR_S1_BASE_OFFSET + (L*N/COEFF_PER_WORD),
    parameter int VECTOR_S1_END_OFFSET = VECTOR_S2_BASE_OFFSET,
    parameter int VECTOR_S2_END_OFFSET = VECTOR_S_END_OFFSET,

    parameter int VECTOR_T_BASE_OFFSET = 0,     //vector t          from calculating t = A*s1 + s2   
    parameter int VECTOR_T_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_T_END_OFFSET = VECTOR_T_BASE_OFFSET + VECTOR_T_TOTAL_WORD,

    parameter int VECTOR_Y_BASE_OFFSET = 0,     //vector y          from expandMask
    parameter int VECTOR_Y_TOTAL_WORD = L * N / COEFF_PER_WORD,
    parameter int VECTOR_Y_END_OFFSET = VECTOR_Y_BASE_OFFSET + VECTOR_Y_TOTAL_WORD,

    parameter int VECTOR_W_BASE_OFFSET = 0,     //vector w          from calculating w = A*y
    parameter int VECTOR_W_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_W_END_OFFSET = VECTOR_W_BASE_OFFSET + VECTOR_W_TOTAL_WORD,

    parameter int VECTOR_C_BASE_OFFSET = 0,     //challenge vector  form NTT(SampleInBall)
    parameter int VECTOR_C_TOTAL_WORD = N / COEFF_PER_WORD,
    parameter int VECTOR_C_END_OFFSET = VECTOR_C_BASE_OFFSET + VECTOR_C_TOTAL_WORD,

    parameter int VECTOR_Z_BASE_OFFSET = 0,    //vector z           from calculating z = y + c*s1
    parameter int VECTOR_Z_TOTAL_WORD = L * N / COEFF_PER_WORD,
    parameter int VECTOR_Z_END_OFFSET = VECTOR_Z_BASE_OFFSET + VECTOR_Z_TOTAL_WORD,  

    parameter int VECTOR_H_BASE_OFFSET = 0,  //vector h          from calculating MakeHint(-c*t0, w - c*s2 + c*t0)
    parameter int VECTOR_H_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_H_END_OFFSET = VECTOR_H_BASE_OFFSET + VECTOR_H_TOTAL_WORD,  
    /* Others BASE OFFSET if need here */
    //TODO
    //NTT calculating parameters
    /* Parameter for NTT module here */
    //TODO
    //SHAKE parameters
    parameter int DATA_IN_BITS = WORD_WIDTH,
    parameter int DATA_OUT_BITS = WORD_WIDTH
)(
    //internal signals
    input  wire                     clk,
    input  wire                     rst,
    input  wire                     start,
    output reg                      done,
    //real time communicating with PS for hashing message
    output reg                              msg_ready,
    input  wire                             msg_valid,
    input  wire [DATA_IN_BITS-1:0]          msg_block,
    input  wire                             msg_last_block,
    input  wire [$clog2(DATA_IN_BITS):0]    msg_block_last_len,
    //raw data RAM signals
    output reg                          ram_we_a_data,
    output reg  [$clog2(TOTAL_WORD):0]  ram_addr_a_data,
    output reg  [WORD_WIDTH-1:0]        ram_din_a_data,
    input  wire [WORD_WIDTH-1:0]        ram_dout_a_data,
    output reg                          ram_we_b_data,
    output reg  [$clog2(TOTAL_WORD):0]  ram_addr_b_data,
    output reg  [WORD_WIDTH-1:0]        ram_din_b_data,
    input  wire [WORD_WIDTH-1:0]        ram_dout_b_data,
    //NTT data RAM signals
    output reg                          ram_we_a_ntt,
    output reg  [$clog2(TOTAL_COEFF):0] ram_addr_a_ntt,
    output reg  [WORD_COEFF-1:0]        ram_din_a_ntt,
    input  wire [WORD_COEFF-1:0]        ram_dout_a_ntt,
    output reg                          ram_we_b_ntt,
    output reg  [$clog2(TOTAL_COEFF):0] ram_addr_b_ntt,
    output reg  [WORD_COEFF-1:0]        ram_din_b_ntt,
    input  wire [WORD_COEFF-1:0]        ram_dout_b_ntt,
    //SHAKE128 signals
    output reg                              shake128_rst,
    output reg  [DATA_IN_BITS-1:0]          shake128_data_in,
    output reg                              shake128_in_valid, 
    output reg                              shake128_in_last, 
    output reg [$clog2(DATA_IN_BITS):0]     shake128_last_len,
    output reg                              shake128_cache_rst,
    output reg                              shake128_cache_rd,
    output reg                              shake128_cache_wr,
    input  wire                             shake128_in_ready,
    output reg                              shake128_out_ready,
    input  wire  [DATA_OUT_BITS-1:0]        shake128_data_out,
    input  wire                             shake128_out_valid,
    //SHAKE256 signals
    output reg                              shake256_rst,
    output reg  [DATA_IN_BITS-1:0]          shake256_data_in,
    output reg                              shake256_in_valid, 
    output reg                              shake256_in_last, 
    output reg [$clog2(DATA_IN_BITS):0]     shake256_last_len,
    output reg                              shake256_cache_rst,
    output reg                              shake256_cache_rd,
    output reg                              shake256_cache_wr,
    input  wire                             shake256_in_ready,
    output reg                              shake256_out_ready,
    input  wire  [DATA_OUT_BITS-1:0]        shake256_data_out,
    input  wire                             shake256_out_valid
    //NTT calculating signals
    /* Put signals for NTT and INTT here */
    //TODO
);
endmodule