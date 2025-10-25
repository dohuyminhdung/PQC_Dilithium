`timescale 1ns / 1ps
// Algorithm 7: Sign a Signature (see FIPS 204 page 25, slide 35)
// Deterministic algorithm to generate a signature for a formatted message M_
// Input: 
//      - private key sk        = read form RAM (no decode) or receive sk then decode 
//      - formatted message M_  = BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ M
//      - context string ctx (a byte string <= 255 bytes)
//      - random seed length 32 bytes to protect system form side channel attack
// Output: signature si

// `define DECODE_SECRET_KEY
//Currently, KeyGen and Sign share the same RAM on a single FPGA, so decoding the secret key is unnecessary.
//Keep the encoded secret key mechanism for software testing purposes.
//If, in the future, the scheme is implemented with KeyGen and Sign running on separate FPGA boards, enable this define
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
    reg [15:0] kappa;                       //kappa at step 8, a value of ExpandMask that generating vector y
    reg [COEFF_WIDTH-1:0] infinityNorm_z;   //compare infinityNorm(z)    >= GAMMA1-BETA ? deny : accept, at step 23
    reg [COEFF_WIDTH-1:0] infinityNorm_r0;  //compare infinityNorm(r0)   >= GAMMA2-BETA ? deny : accept, at step 23
    reg [COEFF_WIDTH-1:0] infinityNorm_ct0; //compare infinityNorm(c*t0) >= GAMMA2      ? deny : accept, at step 28
    reg [$clog2(N*K)  :0] ones_in_vector_h; //compare (number of 1’s in h) > OMEGA      ? deny : accept, at step 28

    // FSM state encoding
    reg [5:0] state, next_state;
    localparam IDLE                 = 0;
    localparam NTT_S1               = 1;    //calculate NTT(s1) in step 2
    localparam NTT_S2               = 2;    //calculate NTT(s2) in step 3
    localparam NTT_T0               = 3;    //calculate NTT(t0) in step 4
    localparam MU_ABSORB_TR         = 4;    //absorb TR in step 6
    localparam MU_ABSORB_MSG        = 5;    //absorb message in step 6
    localparam MU_SQUEEZE           = 6;    //squeeze mu in step 6
    localparam RHO_PP_ABSORB_K      = 7;    //absorb K in step 7
    localparam RHO_PP_ABSORB_RND    = 8;    //absorb random seed from RBG in step 7
    localparam RHO_PP_ABSORB_MU     = 9;    //absorb mu in step 7
    localparam RHO_PP_SQUEEZE       = 10;   //squeeze rho'' in step 7
    localparam EXPAND_MASK          = 11;   //generate vector y in step 11
    localparam CALCULATE_W_0        = 12;   //calculate NTT(y) in step 12
    localparam CALCULATE_W_1        = 13;   //calculate A * NTT(y) in step 12
    localparam CALCULATE_W_2        = 14;   //calculate INTT(A * NTT(y)) in step 12
    localparam C_ABSORB_MU          = 15;   //absorb mu in step 15
    localparam C_ABSORB_HIGH_BITS_W = 16;   //absorb w1Encode(w1) in step 15, note that w1 = HighBits(w) and w1Encode(w1) = w1[0+:4]
    localparam C_SQUEEZE            = 17;   //squeeze c~ in step 15
    localparam SAMPLE_IN_BALL       = 18;   //calculate vector c in step 16
    localparam NTT_C                = 19;   //calculate NTT(c) in step 17
    localparam CALCULATE_CS1_0      = 20;   //calculate c*s1 in step 18
    localparam CALCULATE_CS1_1      = 21;   //calculate INTT(c*s1) in step 18
    localparam CALCULATE_CS2_0      = 22;   //calculate c*s2 in step 19
    localparam CALCULATE_CS2_1      = 23;   //calculate INTT(c*s2) in step 19
    localparam CALCULATE_Z          = 24;   //calculate z in step 20
    localparam VALIDITY_CHECK_0     = 25;   //compare infinityNorm(z) >= GAMMA1-BETA ? deny : accept in step 23
    localparam CALCULATE_R0         = 26;   //calculate r0 = LowBits(w - c*s2) in step 21, 22
    localparam VALIDITY_CHECK_1     = 27;   //compare infinityNorm(r0) >= GAMMA2-BETA ? deny : accept in step 23
    localparam CALCULATE_CT0_0      = 28;   //calculate c*t0 in step 25
    localparam CALCULATE_CT0_1      = 29;   //calculate INTT(c*t0) in step 25
    localparam VALIDITY_CHECK_2     = 30;   //compare infinityNorm(c*t0) >= GAMMA2 ? deny : accept in step 28
    localparam MAKE_HINT_0          = 31;   //calculate w - c*s2 in step 26
    localparam MAKE_HINT_1          = 32;   //calculate w - c*s2 + c*t0 then apply MakeHint in step 26
    localparam VALIDITY_CHECK_3     = 33;   //compare (number of 1's in h) > OMEGA ? deny : accept in step 28
    localparam SIG_ENCODE_Z         = 34;   //encode signature, packing vector z stage in step 33
    localparam SIG_ENCODE_H         = 35;   //encode signature, packing vector h stage in step 33 
`ifdef DECODE_SECRET_KEY
    localparam SK_DECODE_RHO        = 36;   //decode rho from secret key in step 1
    localparam SK_DECODE_K          = 37;   //decode K from secret key in step 1
    localparam SK_DECODE_TR         = 38;   //decode tr from secret key in step 1
    localparam SK_DECODE_S          = 39;   //decode s1, s2 from secret key in step 1
    localparam SK_DECODE_T0         = 40;   //decode t0 from secret key in step 1
    localparam EXPAND_A             = 41;   //generate matrix A in step 5

    //ExpandA instance
    reg                     expandA_start;
    wire                    expandA_done;
    reg  [WORD_WIDTH-1:0]   expandA_rho;
    wire                        expandA_ram_we;
    wire [NTT_ADDR_WIDTH-1:0]   expandA_ram_addr;
    wire [WORD_COEFF-1:0]       expandA_ram_din;
    wire                            expandA_shake_rst;
    wire [DATA_IN_BITS-1:0]         expandA_shake_data_in;
    wire                            expandA_shake_in_valid,
    wire                            expandA_shake_in_last,
    wire [$clog2(DATA_IN_BITS):0]   expandA_shake_last_len, 
    wire                            expandA_shake_cache_rd,
    wire                            expandA_shake_cache_wr,
    wire                            expandA_shake_out_ready,
    reg  [DATA_OUT_BITS-1:0]        expandA_shake_data_out,
    reg                             expandA_shake_out_valid,
    reg                             expandA_shake_in_ready
    ExpandA #( .K(K), .L(L),        .COEFF_PER_WORD(COEFF_PER_WORD),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_BASE_OFFSET(RHO_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .MATRIX_A_BASE_OFFSET(MATRIX_A_BASE_OFFSET)
    ) expandA (.clk(clk),  .rst(rst),  
        .start(expandA_start),
        .done(expandA_done),
        .rho(expandA_rho),
        .we_matA(expandA_ram_we),
        .addr_matA(expandA_ram_addr),
        .din_matA(expandA_ram_din),
        .absorb_next_poly(expandA_shake_rst),
        .shake_data_in(expandA_shake_data_in),
        .in_valid(expandA_shake_in_valid),
        .in_last(expandA_shake_in_last),
        .last_len(expandA_shake_last_len),
        .cache_rd(expandA_shake_cache_rd),
        .cache_wr(expandA_shake_cache_wr),
        .out_ready(expandA_shake_out_ready),
        .shake_data_out(expandA_shake_data_out),
        .out_valid(expandA_shake_out_valid),
        .in_ready(expandA_shake_in_ready)
    );
`endif //DECODE_SECRET_KEY

    //ExpandMask instance
    reg                         expandMask_start;
    wire                        expandMask_done;
    reg  [DATA_IN_BITS-1 : 0]   expandMask_rho;
    wire                        expandMask_ram_we;
    wire [NTT_ADDR_WIDTH-1:0]   expandMask_ram_addr;
    wire [WORD_COEFF-1:0]       expandMask_ram_din;
    wire                            expandMask_shake_rst;
    wire [DATA_IN_BITS-1:0]         expandMask_shake_data_in;
    wire                            expandMask_shake_in_valid;
    wire                            expandMask_shake_in_last;
    wire [$clog2(DATA_IN_BITS):0]   expandMask_shake_last_len;
    wire                            expandMask_shake_cache_rd;
    wire                            expandMask_shake_cache_wr;
    wire                            expandMask_shake_out_ready;
    reg  [DATA_OUT_BITS-1:0]        expandMask_shake_data_out;
    reg                             expandMask_shake_out_valid;
    reg                             expandMask_shake_in_ready;
    ExpandMask #(.L(L),             .GAMMA1(GAMMA1),            .COEFF_PER_WORD(COEFF_PER_WORD),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_Y_OFFSET(RHO_PP_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .VECTOR_Y_BASE_OFFSET(VECTOR_Y_BASE_OFFSET)
    ) expandMask (.clk(clk),  .rst(rst),
        .start(expandMask_start),
        .done(expandMask_done),
        .rho(expandMask_rho),
        .mu(kappa),
        .we_vector_y(expandMask_ram_we),
        .addr_vector_y(expandMask_ram_addr),
        .din_vector_y(expandMask_ram_din),
        .absorb_next_poly(expandMask_shake_rst),
        .shake_data_in(expandMask_shake_data_in),
        .in_valid(expandMask_shake_in_valid),
        .in_last(expandMask_shake_in_last),
        .last_len(expandMask_shake_last_len),
        .cache_rd(expandMask_shake_cache_rd),
        .cache_wr(expandMask_shake_cache_wr),
        .out_ready(expandMask_shake_out_ready),
        .shake_data_out(expandMask_shake_data_out),
        .out_valid(expandMask_shake_out_valid),
        .in_ready(expandMask_shake_in_ready)
    );

    //SampleInBall instance
    reg                         sampleInBall_start;
    wire                        sampleInBall_done;
    reg  [DATA_IN_BITS-1 : 0]   sampleInBall_rho;
    wire                        sampleInBall_ram_we;
    wire [NTT_ADDR_WIDTH-1:0]   sampleInBall_ram_addr;
    wire [WORD_COEFF-1:0]       sampleInBall_ram_din;
    wire [DATA_IN_BITS-1:0]     sampleInBall_shake_data_in;
    wire                        sampleInBall_shake_in_valid;
    wire                        sampleInBall_shake_in_last;
    wire [$clog2(DATA_IN_BITS) : 0] sampleInBall_shake_last_len;
    wire                            sampleInBall_shake_out_ready;
    reg  [DATA_OUT_BITS-1:0]        sampleInBall_shake_data_out;
    reg                             sampleInBall_shake_out_valid;
    reg                             sampleInBall_shake_in_ready;
    SampleInBall #( .LAMBDA(LAMBDA), .TAU(TAU), .COEFF_PER_WORD(COEFF_PER_WORD),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .CHALLENGE_BASE_OFFSET(CHALLENGE_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .VECTOR_C_BASE_OFFSET(VECTOR_C_BASE_OFFSET)
    ) sample_in_ball ( .clk(clk), .rst(rst),
        .start(sampleInBall_start),
        .done(sampleInBall_done),
        .rho(sampleInBall_rho),
        .we_poly_c(sampleInBall_ram_we),
        .addr_poly_c(sampleInBall_ram_addr),
        .din_poly_c(sampleInBall_ram_din),
        .shake_data_in(sampleInBall_shake_data_in),
        .in_valid(sampleInBall_shake_in_valid),
        .in_last(sampleInBall_shake_in_last),
        .last_len(sampleInBall_shake_last_len),
        .out_ready(sampleInBall_shake_out_ready),
        .shake_data_out(sampleInBall_shake_data_out),
        .out_valid(sampleInBall_shake_out_valid),
        .in_ready(sampleInBall_shake_in_ready)
    );

    /* ==================== INTERNAL SIGNALS ==================== */
    localparam HIGH_BITS_LEN = $clog2((Q-1)/(2*GAMMA2)-1);
    localparam LOW_BITS_LEN  = COEFF_WIDTH - HIGH_BITS_LEN;
    //C_ABSORB_HIGH_BITS_W
    localparam W1_WORD_COEFF = HIGH_BITS_LEN * COEFF_PER_WORD;
    localparam W1_BUFFER_SIZE = 256;
    reg [W1_BUFFER_SIZE-1:0]        sign_buffer;
    reg [$clog2(W1_BUFFER_SIZE):0]  sign_buffer_cnt;
    //MAKE_HINT
    localparam VECTOR_HINT_SIZE = $clog2(K*N) + 1;
    // SIG_ENCODE_Z
    localparam Z_COEFF_WORD_LEN = (GAMMA1 + 1) * COEFF_PER_WORD;
    //SIG_ENCODE_H
    localparam HINT_PACK_BOUND = $clog2(OMEGA + K);
    localparam HINT_PACK_BLOCK = (OMEGA + K) * 8 / WORD_WIDTH;
    localparam HINT_COEFF_WORD_LEN = COEFF_PER_WORD * 8;
    reg [HINT_PACK_BOUND-1:0]           hint_pack_index; //Index from Algorithm 20
    reg [11:0]                          hint_base_index; //[11:8] => (0, K), [7:0] => (0,255)
    reg [$clog2(K):0]                   hint_poly_cnt;   //i from h[i]
    reg [K*8 - 1:0]                     hint_poly_store; //index from h[OMEGA + i] = index
    reg [$clog2(HINT_PACK_BLOCK)-1:0]   hint_pack_cnt;   //number of block to write to signature
    /* ==================== INTERNAL SIGNALS ==================== */

    /* ====================  OTHER FUNCTIONS ==================== */
    // Algorithm 36: Decomposition, FIPS 204 page 40, slide 50
    // Decompose(r) = (r1, r0) such that r = r1*(2*gamma2) + r0 mod q, and -gamma2 < r0 <= gamma2
    // Input:  - integer r in Z_q
    // Output: - integer r1 = HighBits(r) - Algorithm 37: High bits, FIPS 204 page 40, slide 50
    //         - integer r0 = LowBits(r)  - Algorithm 38: Low bits,  FIPS 204 page 41, slide 51
    function [HIGH_BITS_LEN-1 : 0] HighBits;
        input [COEFF_WIDTH-1 : 0] w;
        begin
            if     (w <= 1 *GAMMA2) HighBits = 0;
            else if(w <= 3 *GAMMA2) HighBits = 1;
            else if(w <= 5 *GAMMA2) HighBits = 2;
            else if(w <= 7 *GAMMA2) HighBits = 3;
            else if(w <= 9 *GAMMA2) HighBits = 4;
            else if(w <= 11*GAMMA2) HighBits = 5;
            else if(w <= 13*GAMMA2) HighBits = 6;
            else if(w <= 15*GAMMA2) HighBits = 7;
            else if(w <= 17*GAMMA2) HighBits = 8;
            else if(w <= 19 *GAMMA2)HighBits = 9;
            else if(w <= 21*GAMMA2) HighBits = 10;
            else if(w <= 23*GAMMA2) HighBits = 11;
            else if(w <= 25*GAMMA2) HighBits = 12;
            else if(w <= 27*GAMMA2) HighBits = 13;
            else if(w <= 29*GAMMA2) HighBits = 14;
            else if(w <= 31*GAMMA2) HighBits = 15;
            else                    HighBits = 0;
        end
    endfunction

    function [COEFF_WIDTH-1 : 0] LowBits; //component-wise of step 21
        input signed [COEFF_WIDTH-1 : 0] r;
        begin
            if      (r <= 1 *GAMMA2) LowBits = r - 0  * 2 * GAMMA2;
            else if (r <= 3 *GAMMA2) LowBits = r - 1  * 2 * GAMMA2;
            else if (r <= 5 *GAMMA2) LowBits = r - 2  * 2 * GAMMA2;
            else if (r <= 7 *GAMMA2) LowBits = r - 3  * 2 * GAMMA2;
            else if (r <= 9 *GAMMA2) LowBits = r - 4  * 2 * GAMMA2;
            else if (r <= 11*GAMMA2) LowBits = r - 5  * 2 * GAMMA2;
            else if (r <= 13*GAMMA2) LowBits = r - 6  * 2 * GAMMA2;
            else if (r <= 15*GAMMA2) LowBits = r - 7  * 2 * GAMMA2;
            else if (r <= 17*GAMMA2) LowBits = r - 8  * 2 * GAMMA2;
            else if (r <= 19*GAMMA2) LowBits = r - 9  * 2 * GAMMA2;
            else if (r <= 21*GAMMA2) LowBits = r - 10 * 2 * GAMMA2;
            else if (r <= 23*GAMMA2) LowBits = r - 11 * 2 * GAMMA2;
            else if (r <= 25*GAMMA2) LowBits = r - 12 * 2 * GAMMA2;
            else if (r <= 27*GAMMA2) LowBits = r - 13 * 2 * GAMMA2;
            else if (r <= 29*GAMMA2) LowBits = r - 14 * 2 * GAMMA2;
            else if (r <= 31*GAMMA2) LowBits = r - 15 * 2 * GAMMA2;
            else                    LowBits = r - 16 * 2 * GAMMA2;
        end
    endfunction
    function [WORD_COEFF-1 : 0] LowBits_r0;
        input [WORD_COEFF-1 : 0] word_coeff;
        begin
            LowBits_r0 = {  LowBits(word_coeff[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                            LowBits(word_coeff[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                            LowBits(word_coeff[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                            LowBits(word_coeff[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
        end
    endfunction

    // Calculate Infinity Norm of a word of 4 coefficient (in a polynomial of a vector / matrix)
    function [COEFF_WIDTH-1:0] infinityNorm;
        input [WORD_COEFF-1:0] word_coeff;
        input unsigned [COEFF_WIDTH-1:0] cur_infinityNorm;
        localparam HALF_Q = Q >> 1;

        int signed coeff[0:3];
        int unsigned abs_val[0:3];
        int unsigned max, max1, max2;
        begin
            for (int i = 0; i < 4; i = i + 1) begin
                coeff[i] = word_coeff[i * COEFF_WIDTH +: COEFF_WIDTH];
                if (coeff[i] < 0) 
                    abs_val[i] = -coeff[i];
                else
                    abs_val[i] = (coeff[i] > HALF_Q) ? (Q - coeff[i]) : coeff[i];
            end

            max1 = (abs_val[3] > abs_val[2]) ? abs_val[3] : abs_val[2];
            max2 = (abs_val[1] > abs_val[0]) ? abs_val[1] : abs_val[0];
            max = (max1 > max2) ? max1 : max2;
            infinityNorm = (max > cur_infinityNorm) ? max : cur_infinityNorm;
        end
    endfunction

    // Algorithm 39: Making hints, FIPS 204 page 41, slide 51
    // Computes hint bit indicating whether adding z to r alters the high bits of r.
    // TODO: explaning why using -z instead of z
    // Input : integers z, r in Z_q
    // Output: boolean
    function MakeHint;
        input [COEFF_WIDTH-1 : 0]   z, r;
        logic [COEFF_WIDTH : 0]     sum_mod_q;
        logic [HIGH_BITS_LEN-1 : 0] hb_z, hb_r;
        integer sum;
        begin
            sum = -z + r; 
            if (sum <= 0)
                sum_mod_q = sum + Q;
            else if (sum < Q) 
                sum_mod_q = sum;
            else
                sum_mod_q = sum - Q; 
            
            hb_r = HighBits(r);
            hb_z = HighBits(sum_mod_q);
            MakeHint = (hb_r != hb_z);
        end
    endfunction

    // task MakeHintCoeffs;
    //     input  [WORD_COEFF-1:0] z, r;
    //     output [WORD_COEFF-1:0] hint_wr;
    //     output [VECTOR_HINT_SIZE-1:0] hint_cnt;

    //     logic [COEFF_WIDTH-1 : 0] z_coeff[0:3], r_coeff[0:3];
    //     logic hint[0:3];
    //     integer i;
    //     begin
    //         for(i = 0; i < 4; i = i + 1) begin
    //             z_coeff[i] = z[i * COEFF_WIDTH +: COEFF_WIDTH];
    //             r_coeff[i] = r[i * COEFF_WIDTH +: COEFF_WIDTH];
    //             hint[i] = MakeHint(z_coeff[i], r_coeff[i]);
    //             hint_wr[i * COEFF_WIDTH +: COEFF_WIDTH] = {{(COEFF_WIDTH-1){1'b0}}, hint[i]};
    //             hint_cnt = hint_cnt + hint[i]; 
    //         end
    //     end
    // endtask
    function [WORD_COEFF-1:0] MakeHintWr;
        input [WORD_COEFF-1:0]  z, r;
        logic [COEFF_WIDTH-1:0] z_coeff[0:3], r_coeff[0:3];
        logic hint[0:3];
        integer i;
        begin
            for(i = 0; i < 4; i = i + 1) begin
                z_coeff[i] = z[i * COEFF_WIDTH +: COEFF_WIDTH];
                r_coeff[i] = r[i * COEFF_WIDTH +: COEFF_WIDTH];
                hint[i] = MakeHint(z_coeff[i], r_coeff[i]);
                MakeHintWr[i * COEFF_WIDTH +: COEFF_WIDTH] = {{(COEFF_WIDTH-1){1'b0}}, hint[i]};
            end
        end
    endfunction
    function [VECTOR_HINT_SIZE-1:0] MakeHintCnt;
        input [WORD_COEFF-1:0]  z, r;
        logic [COEFF_WIDTH-1:0] z_coeff[0:3], r_coeff[0:3];
        logic hint[0:3];
        integer i;
        begin
            MakeHintCnt = '0;
            for(i = 0; i < 4; i = i + 1) begin
                z_coeff[i] = z[i * COEFF_WIDTH +: COEFF_WIDTH];
                r_coeff[i] = r[i * COEFF_WIDTH +: COEFF_WIDTH];
                hint[i] = MakeHint(z_coeff[i], r_coeff[i]);
                MakeHintCnt = MakeHintCnt + hint[i]; 
            end
        end
    endfunction

    function [GAMMA1 : 0] BitPack_vector_z;
        input [COEFF_WIDTH-1:0] z;
        begin
            BitPack_vector_z = gamma1 - z;
        end
    endfunction

    // Algorithm 20: Hint bit packing, FIPS 204 page 32, slide 42
    // Process 4 coeff per call
    function [HINT_COEFF_WORD_LEN-1:0] HintBitPack4Coeff;
        input [WORD_COEFF-1 : 0] word_coeff;
        input [7:0] base_index; //(0-255)
        logic [COEFF_WIDTH-1:0] coeff[0:3];
        logic valid[0:3];
        integer i, j;
        begin
            j = 0;
            HintBitPack4Coeff = '0;
            for(i = 0; i < 4; i = i + 1) begin
                coeff[i] = word_coeff[i * COEFF_WIDTH +: COEFF_WIDTH];
                valid[i] = (coeff[i] != 0);
                if (valid[i]) begin
                    HintBitPack4Coeff[j*8 +: 8] = base_index + j;
                    j = j + 1;
                end
            end
        end
    endfunction

    function [HINT_PACK_BOUND-1 : 0] HintBitPackIndex;
        input [WORD_COEFF-1 : 0] word_coeff;
        logic [COEFF_WIDTH-1:0] coeff[0:3];
        logic valid[0:3];
        begin
            coeff[0] = word_coeff[0 * COEFF_WIDTH +: COEFF_WIDTH];
            coeff[1] = word_coeff[1 * COEFF_WIDTH +: COEFF_WIDTH];
            coeff[2] = word_coeff[2 * COEFF_WIDTH +: COEFF_WIDTH];
            coeff[3] = word_coeff[3 * COEFF_WIDTH +: COEFF_WIDTH];
            
            valid[0] = (coeff[0] != 0);
            valid[1] = (coeff[1] != 0);
            valid[2] = (coeff[2] != 0);
            valid[3] = (coeff[3] != 0);

            HintBitPackIndex = valid[0] + valid[1] + valid[2] + valid[3]; 
        end
    endfunction
    /* ====================  OTHER FUNCTIONS ==================== */

    always @(posedge clk) begin
        if (rst) begin
            state <= IDLE;
        end else begin
            state <= next_state;
        end
    end

    always @* begin
        next_state = state;
        case(state)
            IDLE: begin
                `ifndef DECODE_SECRET_KEY
                if(start) next_state = NTT_S1;
                `else  //DECODE_SECRET_KEY
                if(start) next_state = SK_DECODE_RHO;
                `endif //DECODE_SECRET_KEY
            end
`ifdef DECODE_SECRET_KEY
            SK_DECODE_RHO: begin
                next_state = SK_DECODE_K;
            end
            SK_DECODE_K: begin
                next_state = SK_DECODE_TR;
            end
            SK_DECODE_TR: begin
                next_state = SK_DECODE_S;
            end
            SK_DECODE_S: begin
                next_state = SK_DECODE_T0;
            end
            SK_DECODE_T0: begin
                next_state = EXPAND_A;
            end
            EXPAND_A: begin
                next_state = NTT_S1;
            end
`endif //DECODE_SECRET_KEY
            NTT_S1: begin
            end
            NTT_S2: begin
            end
            NTT_T0: begin
            end
            MU_ABSORB_TR: begin
                if(ram_addr_b_data >= TR_END_OFFSET-1)
                    next_state = MU_ABSORB_MSG;
            end
            MU_ABSORB_MSG: begin
                if(msg_last_block)
                    next_state = MU_SQUEEZE;
            end
            MU_SQUEEZE: begin
                if(ram_addr_a_data >= MU_END_OFFSET-1)
                    next_state = RHO_PP_ABSORB_K;
            end
            RHO_PP_ABSORB_K: begin
                if(ram_addr_b_data >= K_END_OFFSET)
                    next_state = RHO_PP_ABSORB_RND;
            end
            RHO_PP_ABSORB_RND: begin
                if(ram_addr_b_data >= RND_END_OFFSET)
                    next_state = RHO_PP_ABSORB_MU;
            end
            RHO_PP_ABSORB_MU: begin
                if(ram_addr_b_data >= MU_END_OFFSET-1)
                    next_state = RHO_PP_SQUEEZE;
            end
            RHO_PP_SQUEEZE: begin
                if(ram_addr_a_data >= RHO_PP_END_OFFSET-1)
                    next_state = EXPAND_MASK;
            end
            EXPAND_MASK: begin
                if(expandMask_done)
                    next_state = CALCULATE_W_0;
            end
            CALCULATE_W_0: begin
            end
            CALCULATE_W_1: begin
            end
            CALCULATE_W_2: begin
            end
            C_ABSORB_MU: begin
                if(ram_addr_b_data >= MU_END_OFFSET-1)
                    next_state = C_ABSORB_HIGH_BITS_W;
            end
            C_ABSORB_HIGH_BITS_W: begin
                if(shake256_in_last)
                    next_state = C_SQUEEZE;
            end
            C_SQUEEZE: begin
                if(ram_addr_a_data >= CHALLENGE_END_OFFSET-1)
                    next_state = SAMPLE_IN_BALL;
            end
            SAMPLE_IN_BALL: begin
                if (sampleInBall_done)
                    next_state = NTT_C;
            end
            NTT_C: begin
            end
            CALCULATE_CS1_0: begin
            end
            CALCULATE_CS1_1: begin
            end
            CALCULATE_CS2_0: begin
            end
            CALCULATE_CS2_1: begin
            end
            CALCULATE_Z: begin
            end
            VALIDITY_CHECK_0: begin
                if(infinityNorm_z >= (gamma1 - BETA))
                    next_state = EXPAND_MASK;
                else
                    next_state = CALCULATE_R0;
            end
            CALCULATE_R0: begin
            end
            VALIDITY_CHECK_1: begin
                if(infinityNorm_r0 >= (GAMMA2 - BETA))
                    next_state = EXPAND_MASK;
                else
                    next_state = CALCULATE_CT0_0;
            end
            CALCULATE_CT0_0: begin
            end
            CALCULATE_CT0_1: begin
            end
            VALIDITY_CHECK_2: begin
                if(infinityNorm_ct0 >= GAMMA2)
                    next_state = EXPAND_MASK;
                else
                    next_state = MAKE_HINT_0;
            end
            MAKE_HINT_0: begin
            end
            MAKE_HINT_1: begin
            end
            VALIDITY_CHECK_3: begin
                if(ones_in_vector_h > OMEGA)
                    next_state = EXPAND_MASK;
                else
                    next_state = SIG_ENCODE_Z;
            end
            SIG_ENCODE_Z: begin
                if((ram_addr_b_ntt >= VECTOR_Z_END_OFFSET-1) && sign_buffer_cnt == 0)
                    next_state = SIG_ENCODE_H;
            end
            SIG_ENCODE_H: begin
                if(hint_pack_cnt >= HINT_PACK_BLOCK)
                    next_state = IDLE;
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            //TODO: Reset signals that shall reset
        end else begin
            case(state)
                IDLE: begin
                    done <= 0;
                    kappa <= 0;
                    msg_ready <= 0;
                    infinityNorm_z <= 0;
                    infinityNorm_r0 <= 0;
                    infinityNorm_ct0 <= 0;
                    ones_in_vector_h <= 0;
                    //TODO: Reset signals that should reset
                end
    `ifdef DECODE_SECRET_KEY //Currently do not implement these
                SK_DECODE_RHO: begin
                end
                SK_DECODE_K: begin
                end
                SK_DECODE_TR: begin
                end
                SK_DECODE_S: begin
                end
                SK_DECODE_T0: begin
                end
                EXPAND_A: begin
                end
    `endif //DECODE_SECRET_KEY
                NTT_S1: begin
                end
                NTT_S2: begin
                end
                NTT_T0: begin
                end
                MU_ABSORB_TR: begin
                    shake256_in_valid <= 0;
                    if(shake256_in_ready) begin
                        shake256_in_valid <= 1;
                        shake256_in_last <= 0;
                        shake256_last_len <= 0;
                        shake256_data_in <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data + 1; 
                    end
                end
                MU_ABSORB_MSG: begin
                    shake256_data_in <= msg_block;
                    shake256_in_valid <= msg_valid;
                    shake256_in_last <= msg_last_block;
                    shake256_last_len <= msg_block_last_len;
                    msg_ready <= shake256_in_ready;
                    //out_ready <= 0;
                    if(msg_last_block) begin
                        shake256_out_ready <= 1;
                        ram_addr_a_data <= MU_BASE_OFFSET-1;
                    end
                end
                MU_SQUEEZE: begin
                    ram_we_a_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= shake256_data_out;
                    end
                    if(ram_addr_a_data >= MU_END_OFFSET-1) begin //setup for next state
                        shake256_rst <= 1;
                        ram_addr_b_data <= K_BASE_OFFSET - 1;
                    end
                end
                RHO_PP_ABSORB_K: begin
                    shake256_rst <= 0;
                    shake256_in_valid <= 0;
                    if(shake256_in_ready) begin
                        shake256_in_valid <= 1;
                        shake256_in_last <= 0;
                        shake256_last_len <= 0;
                        shake256_data_in <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data == K_END_OFFSET ?
                                            RND_BASE_OFFSET : ram_addr_b_data + 1; 
                    end
                end
                RHO_PP_ABSORB_RND: begin
                    shake256_data_in <= ram_dout_b_data;
                    ram_addr_b_data <= ram_addr_b_data == RND_END_OFFSET ?
                                        MU_BASE_OFFSET : ram_addr_b_data + 1; 
                end
                RHO_PP_ABSORB_MU: begin
                    shake256_data_in <= ram_dout_b_data;
                    ram_addr_b_data <= ram_addr_b_data + 1;
                    if(ram_addr_b_data >= MU_END_OFFSET-1) begin //setup for next state
                        shake256_in_last <= 1;
                        shake256_last_len <= WORD_WIDTH;
                        ram_addr_a_data = RHO_PP_BASE_OFFSET - 1;
                    end
                end
                RHO_PP_SQUEEZE: begin
                    ram_we_a_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= shake256_data_out;
                    end
                    if(ram_addr_a_data >= RHO_PP_END_OFFSET-1) begin
                        expandMask_start <= 1;
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                    end
                end
                EXPAND_MASK: begin
                    ram_we_a_ntt <= expandMask_ram_we;
                    ram_addr_a_ntt <= expandMask_ram_addr;
                    ram_din_a_ntt <= expandMask_ram_din;

                    //For ExpandMask's absorb state, may need refactor that this state feed rho instead of the module
                    shake256_rst <= expandMask_shake_rst;
                    shake256_data_in <= expandMask_shake_data_in;
                    shake256_in_valid <= expandMask_shake_in_valid;
                    shake256_in_last <= expandMask_shake_in_last;
                    shake256_last_len <= expandMask_shake_last_len;
                    shake256_cache_rd <= expandMask_shake_cache_rd;
                    shake256_cache_wr <= expandMask_shake_cache_wr;
                    shake256_out_ready <= expandMask_shake_out_ready;

                    expandMask_shake_data_out <= shake256_data_out;
                    expandMask_shake_out_valid <= shake256_out_valid;
                    expandMask_shake_in_ready <= shake256_in_ready;

                    if(expandMask_start) begin
                        expandMask_start <= 0;
                        shake256_rst <= 0;
                        shake256_cache_rst <= 0;
                        ram_addr_b_data <= RHO_PP_BASE_OFFSET;
                    end else if(ram_addr_b_data < RHO_PP_END_OFFSET) begin
                        //in_valid = 1;
                        expandMask_rho <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                    end else if (expandMask_done) begin //setup for next state
                        shake256_rst <= 1;
                        //TODO: setup for next calculating vector w if need 
                    end
                end
                CALCULATE_W_0: begin
                    shake256_rst <= 0;
                    //TODO
                end
                CALCULATE_W_1: begin
                    //TODO
                end
                CALCULATE_W_2: begin
                    //TODO
                end
                C_ABSORB_MU: begin
                    shake256_in_valid <= 0;
                    if(shake256_in_ready) begin
                        shake256_in_valid <= 1;
                        shake256_in_last <= 0;
                        shake256_last_len <= 0;
                        shake256_data_in <= ram_dout_b_data;
                        ram_addr_b_data  <= ram_addr_b_data + 1; 
                    end
                    if(ram_addr_b_data >= MU_END_OFFSET-1) begin //setup for next state
                        ram_addr_b_ntt <= VECTOR_W_BASE_OFFSET;
                        sign_buffer_cnt <= 0;
                        sign_buffer <= 0;
                    end
                end
                C_ABSORB_HIGH_BITS_W: begin
                    shake256_in_valid <= 0;
                    if(shake256_in_ready && sign_buffer_cnt >= DATA_IN_BITS) begin
                        shake256_in_valid <= 1;
                        shake256_data_in <= sign_buffer[0+:DATA_IN_BITS];
                        sign_buffer_cnt <= sign_buffer_cnt - DATA_IN_BITS;
                        sign_buffer <= sign_buffer >> DATA_IN_BITS;
                    end else if (sign_buffer_cnt <= W1_BUFFER_SIZE - W1_WORD_COEFF) begin
                        sign_buffer_cnt <= sign_buffer_cnt + W1_WORD_COEFF;
                        sign_buffer[sign_buffer_cnt+:W1_WORD_COEFF] <= {HighBits(ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                    HighBits(ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                    HighBits(ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                    HighBits(ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH])};
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                    end
                    if(ram_addr_b_ntt >= VECTOR_W_END_OFFSET-1) begin
                        //turn on last absorb block flag for shake256
                        shake256_in_last <= 1;
                        shake256_last_len <= DATA_IN_BITS;
                        shake256_out_ready <= 1;
                        //setup for next state
                        ram_addr_a_data <= CHALLENGE_BASE_OFFSET-1;
                    end
                end
                C_SQUEEZE: begin
                    ram_we_a_data <= 0;
                    shake256_in_last <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= shake256_data_out;
                    end
                    if(ram_addr_a_data >= CHALLENGE_END_OFFSET-1) begin //setup for next state
                        sampleInBall_start <= 1;
                        shake256_rst <= 1;
                    end
                end
                SAMPLE_IN_BALL: begin
                    ram_we_a_ntt <= sampleInBall_ram_we;
                    ram_addr_a_ntt <= sampleInBall_ram_addr;
                    ram_din_a_ntt <= sampleInBall_ram_din;

                    //For SampleInBall absorb state, may need refactor that this state feed rho instead of the module
                    shake256_data_in <= sampleInBall_shake_data_in;
                    shake256_in_valid <= sampleInBall_shake_in_valid;
                    shake256_in_last <= sampleInBall_shake_in_last;
                    shake256_last_len <= sampleInBall_shake_last_len;
                    shake256_out_ready <= sampleInBall_shake_out_ready;

                    sampleInBall_shake_data_out <= shake256_data_out;
                    sampleInBall_shake_out_valid <= shake256_out_valid;
                    sampleInBall_shake_in_ready <= shake256_in_ready;

                    if(sampleInBall_start) begin                             //at this clock, SHAKE begin to reset
                        sampleInBall_start <= 0;
                        shake256_rst <= 0;
                        ram_addr_a_data <= CHALLENGE_BASE_OFFSET;       //setup first absorb block of rho
                    end else if(ram_addr_a_data < CHALLENGE_END_OFFSET) begin
                        // in_valid <= 1;
                        sampleInBall_rho <= ram_dout_a_data;             //feed next block data of rho'
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if (sampleInBall_done) begin                //wait done and setup for next NTT_C state
                        //TODO: setup for next state calculating NTT(c) 
                    end
                end
                NTT_C: begin
                end
                CALCULATE_CS1_0: begin
                end
                CALCULATE_CS1_1: begin
                end
                CALCULATE_CS2_0: begin
                end
                CALCULATE_CS2_1: begin
                end
                CALCULATE_Z: begin
                    if(/*final write a word of 4 coefficient*/)
                        infinityNorm_z <= infinityNorm(/*ram_din_a_ntt or ram_din_b_ntt or something else*/, infinityNorm_z);
                end
                VALIDITY_CHECK_0: begin
                    if(infinityNorm_z >= (gamma1 - BETA)) begin //reject this result, setup for re-computing expandMask
                        expandMask_start <= 1;
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                        kappa <= kappa + L;
                    end else begin                              //accept this result, setup for next state
                        //TODO: setup for next state calculating r0
                    end
                end
                CALCULATE_R0: begin
                    if(/*final write a word of 4 coefficient*/)
                        infinityNorm_r0 <= infinityNorm(LowBits_r0(/*ram_din_a_ntt or ram_din_b_ntt or something else*/), infinityNorm_r0);
                end
                VALIDITY_CHECK_1: begin
                    if(infinityNorm_r0 >= (GAMMA2 - BETA)) begin //reject this result, setup for re-computing expandMask
                        expandMask_start <= 1;
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                        kappa <= kappa + L;
                    end else begin                              //accept this result, setup for next state
                        //TODO: setup for next state calculating c * t0
                    end
                end
                CALCULATE_CT0_0: begin
                end
                CALCULATE_CT0_1: begin
                    if(/*final write a word of 4 coefficient*/)
                        infinityNorm_ct0 <= infinityNorm(/*ram_din_a_ntt or ram_din_b_ntt or something else*/, infinityNorm_ct0);
                end
                VALIDITY_CHECK_2: begin
                    if(infinityNorm_ct0 >= GAMMA2) begin //reject this result, setup for re-computing expandMask
                        expandMask_start <= 1;
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                        kappa <= kappa + L;
                    end else begin                              //accept this result, setup for next state
                        //TODO: setup for next state calculating w - c*s2
                    end
                end
                MAKE_HINT_0: begin
                end
                MAKE_HINT_1: begin
                    if(/*final write a word of 4 coefficient*/) begin
                        //MakeHintCoeffs(/*   c*t0, w - c*s2 + c*t0, ram_din_ntt,  */ ones_in_vector_h);
                        /* ram_din_ntt */ <= MakeHintWr(/*c*t0, w - c*s2 + c*t0*/);
                        ones_in_vector_h <= ones_in_vector_h + MakeHintCnt(/*c*t0, w - c*s2 + c*t0*/);
                    end
                end
                VALIDITY_CHECK_3: begin
                    if(ones_in_vector_h > OMEGA) begin
                        expandMask_start <= 1;
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                        kappa <= kappa + L;
                    end else begin  //setup for next state
                        ram_addr_b_ntt <= VECTOR_Z_BASE_OFFSET;
                        ram_addr_a_data <= CHALLENGE_END_OFFSET;
                        sign_buffer_cnt <= 0;
                    end
                end
                SIG_ENCODE_Z: begin
                    if(sign_buffer_cnt >= WORD_WIDTH) begin
                        //write vector z to signature
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= sign_buffer[0+:WORD_WIDTH];
                        sign_buffer_cnt <= sign_buffer_cnt - WORD_WIDTH;
                        sign_buffer <= sign_buffer >> WORD_WIDTH; 
                    end else begin
                        if(ram_addr_b_ntt >= VECTOR_Z_END_OFFSET-1) begin
                            ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                            sign_buffer_cnt <= sign_buffer_cnt + Z_COEFF_WORD_LEN;
                            sign_buffer[sign_buffer_cnt+:Z_COEFF_WORD_LEN] <= { BitPack_vector_z(ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                                BitPack_vector_z(ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                                BitPack_vector_z(ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                                BitPack_vector_z(ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
                        end else begin  //setup for next state
                            ram_addr_b_ntt <= VECTOR_H_BASE_OFFSET;
                            sign_buffer <= 0;
                            sign_buffer_cnt <= 0;
                            hint_pack_index <= 0;
                            hint_base_index <= 0;
                            hint_poly_cnt <= 0;
                            hint_poly_store <= 0;
                            hint_pack_cnt <= 0;
                        end
                    end 
                end
                SIG_ENCODE_H: begin
                    //final block will only have 3 significantly byte
                    //encode 4 coeff each clk
                    if(sign_buffer_cnt >= WORD_WIDTH) begin
                        //write hint to signature
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= sign_buffer[0+:WORD_WIDTH];
                        sign_buffer_cnt <= sign_buffer_cnt - WORD_WIDTH;
                        sign_buffer <= sign_buffer >> WORD_WIDTH; 
                        hint_pack_cnt <= hint_pack_cnt + 1;
                    end else if(ram_addr_b_ntt < VECTOR_H_END_OFFSET) begin
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                        sign_buffer_cnt <= sign_buffer_cnt + (HintBitPackIndex(ram_dout_b_ntt) << 3); // * 8
                        sign_buffer[sign_buffer_cnt+:HINT_COEFF_WORD_LEN] <= HintBitPack4Coeff(ram_dout_b_ntt, hint_base_index[0+:8]);
                        hint_base_index <= hint_base_index + 4;
                        hint_pack_index <= hint_pack_index + HintBitPackIndex(ram_dout_b_ntt);
                        
                        if((hint_base_index != 0) && hint_base_index[0+:8] == 0) begin //pack y[omega + k]
                            hint_poly_cnt <= hint_poly_cnt + 1;
                            hint_poly_store[hint_poly_cnt * 8 +: 8] <= hint_pack_index + HintBitPackIndex(ram_dout_b_ntt);
                        end
                    end else begin
                        if(hint_pack_cnt < HINT_PACK_BLOCK - 1) begin
                             //write zero's filler to signature
                            ram_we_a_data <= 1;
                            ram_addr_a_data <= ram_addr_a_data + 1;
                            ram_din_a_data <= sign_buffer[0+:WORD_WIDTH];
                            sign_buffer_cnt <= sign_buffer_cnt - WORD_WIDTH;
                            sign_buffer <= 0; 
                            hint_pack_cnt <= hint_pack_cnt + 1;
                        end else if (hint_pack_cnt == HINT_PACK_BLOCK - 1) begin
                            ram_we_a_data <= 1;
                            ram_addr_a_data <= ram_addr_a_data + 1;
                            ram_din_a_data <= { hint_poly_store[0+:5*8], //5 bytes from indexing polynomial
                                                sign_buffer[0+:(3*8)] }; //3 byte from indexing omega 
                        end else begin
                            ram_we_a_data <= 1;
                            ram_addr_a_data <= ram_addr_a_data + 1;
                            ram_din_a_data <= { {( WORD_WIDTH - 3*8 ){1'b0}}, //zero fill
                                                hint_poly_store[0+:3*8] };    //last 3 byte
                            done <= 1;
                        end
                    end
                end
            endcase
        end
    end
endmodule