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
    parameter int LAMBDA = 256          //collision strength of challenge c~
    parameter int GAMMA1 = 19,          //2^GAMMA1 = coeff range of vector y
    parameter int GAMMA2 = (Q-1)/32,    //low-order rounding range
    parameter int K = 8,                //number of rows of matrix A
    parameter int L = 7,                //number of cols of matrix A
    parameter int ETA = 2,              //the bound for coefficients of secret vectors s1, s2
    parameter int BETA = TAU * ETA,     //valid check constant in step 23
    parameter int OMEGA = 75,           //max number of 1's in the hint vector h 
    parameter int KAPPA_BOUND = 814*L,  //Appendix C - Loop Bounds for ML-DSA.Sign_internal
                                        //FIPS204, page 52, slide 62
    //raw data RAM parameters
    parameter int WORD_WIDTH = 64,
    parameter int TOTAL_WORD = 4096,
    parameter int DATA_ADDR_WIDTH = $clog2(TOTAL_WORD),

    parameter int RHO_BASE_OFFSET = 0,          //seed rho for expandA
    parameter int RHO_END_OFFSET = RHO_BASE_OFFSET + (32*8/WORD_WIDTH),

    parameter int RHO_PRIME_BASE_OFFSET = 0,    //seed rho' for expandS
    parameter int RHO_PRIME_END_OFFSET = RHO_PRIME_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int PUBLIC_KEY_SIZE = (32 + 32 * K * ($clog2(q-1) - D)) * 8, //2592 bytes for ML-DSA87
    parameter int PUBLIC_KEY_END_OFFSET = PUBLIC_KEY_BASE_OFFSET + (PUBLIC_KEY_SIZE/WORD_WIDTH),

    parameter int SECRET_KEY_BASE_OFFSET = 0,   //rho, K, tr, s1.encode, s2.encode, t0
    parameter int SECRET_KEY_SIZE = (32 + 32 + 64 + 32 * ((K+L) * $clog2(ETA*2+1) + D * K)), //4896 bytes for ML-DSA87
    parameter int SECRET_KEY_END_OFFSET = SECRET_KEY_BASE_OFFSET + SECRET_KEY_SIZE,  

    parameter int K_BASE_OFFSET = SECRET_KEY_BASE_OFFSET + (32*8/WORD_WIDTH),   //K is use for signing
    parameter int K_END_OFFSET = K_BASE_OFFSET + (32*8/WORD_WIDTH),

    parameter int TR_BASE_OFFSET = K_BASE_OFFSET + (32*8/WORD_WIDTH)            //tr is use for signing
    parameter int TR_END_OFFSET  = TR_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int RHO_Y_BASE_OFFSET = 0,        //seed rho'' for expandMask
    parameter int CHALLENGE_BASE_OFFSET = 0,    //seed rho for SampleInBall
    parameter int COMMITMENT_BASE_OFFSET = 0,   //address of c~ at step 15
    parameter int SIGNATURE_BASE_OFFSET = COMMITMENT_BASE_OFFSET,
    parameter int MESSAGE_BASE_OFFSET = 0;  //message to sign, M' = BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ M
                                            // TR || BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ M
                                            // Let software handle concating ctx with message: TR || M'

    parameter int MU_BASE_OFFSET = 0,       //seed after hashing message in step 6
    parameter int MU_END_OFFSET = MU_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int RND_BASE_OFFSET = 0,      //rnd seed for absorbing in step 7
    parameter int RND_END_OFFSET = RND_BASE_OFFSET + (32*8/WORD_WIDTH), 

    parameter int RHO_PP_BASE_OFFSET = 0,   //seed rho'' for expandMask
    parameter int RHO_PP_END_OFFSET = RHO_PP_BASE_OFFSET + (64*8/WORD_WIDTH),
    //NTT data RAM parameters
    parameter int COEFF_WIDTH = 24,
    parameter int COEFF_PER_WORD = 4,
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
    parameter int VECTOR_T_END_OFFSET = VECTOR_T_BASE_OFFSET + VECTOR_T_TOTAL_WORD;   

    parameter int VECTOR_Y_BASE_OFFSET = 0,     //vector y          from expandMask
    parameter int VECTOR_Y_TOTAL_WORD = L * N / COEFF_PER_WORD,
    parameter int VECTOR_Y_END_OFFSET = VECTOR_Y_BASE_OFFSET + VECTOR_Y_TOTAL_WORD,

    parameter int VECTOR_W_BASE_OFFSET = 0,     //vector w          from calculating w = A*y
    parameter int VECTOR_W_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_W_END_OFFSET = VECTOR_W_BASE_OFFSET + VECTOR_W_TOTAL_WORD,

    parameter int VECTOR_C_BASE_OFFSET = 0,     //challenge vector  form NTT(SampleInBall)
    parameter int VECTOR_W1_BASE_OFFSET = 0,    //vector w1         from calculating w1 = HighBits(w)
    parameter int VECTOR_S1_BASE_OFFSET = VECTOR_S_BASE_OFFSET,
    parameter int VECTOR_S2_BASE_OFFSET = VECTOR_S1_BASE_OFFSET + (L*N/COEFF_PER_WORD); 
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
    input  wire [WORD_WIDTH-1:0]        ram_dout_a_data,
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
    localparam gamma1 = 1 << GAMMA1;
    reg [$clog2(KAPPA_BOUND)-1:0] kappa;

    // FSM state encoding
    reg [5:0] state, next_state;
    localparam IDLE             = 0;
    localparam NTT_S1           = 1;
    localparam NTT_S2           = 2;
    localparam NTT_T0           = 3;
    localparam MU_ASBORB_TR     = 4;    //absorb TR in step 6
    localparam MU_ABSORB_MSG    = 5;    //absorb message in step 6
    localparam MU_SQUEEZE       = 6;    //squeeze mu in step 6
    localparam RHO_PP_ABSORB_K  = 7;    //absorb K in step 7
    localparam RHO_PP_ABSORB_RND= 8;    //absorb random seed from RBG in step 7
    localparam RHO_PP_ABSORB_MU = 9;    //absorb mu in step 7
    localparam RHO_PP_SQUEEZE   = 10;   //squeeze rho'' in step 7
    localparam EXPAND_MASK      = 11;   //generate vector y
    localparam CALCULATE_W_0    = 12;   //calculate NTT(y)
    localparam CALCULATE_W_1    = 13;   //calculate A * NTT(y)
    localparam CALCULATE_W_2    = 14;   //calculate INTT(A * NTT(y))
    localparam HIGH_BITS_W      = 15;
    localparam HASH_COMMITMENT  = 16;
    localparam SAMPLE_IN_BALL   = 17;
    localparam NTT_C            = 18;
    localparam CALCULATE_CS1_0  = 19;   //calculate c*s1
    localparam CALCULATE_CS1_1  = 20;   //calculate INTT(c*s1)
    localparam CALCULATE_CS2_0  = 21;   //calculate c*s2
    localparam CALCULATE_CS2_1  = 22;   //calculate INTT(c*s2)
    localparam CALCULATE_Z      = 23;
    localparam VALIDITY_CHECK_0 = 24;   //compare infinityNorm(z) >= GAMMA1-BETA ? deny : accept
    localparam LOW_BITS_0       = 25;   //calculate w - c*s2
    localparam LOW_BITS_1       = 26;   //calculate r0
    localparam VALIDITY_CHECK_1 = 27;   //compare infinityNorm(r0) >= GAMMA2-BETA ? deny : accept
    localparam CALCULATE_CT0_0  = 28;   //calculate c*t0
    localparam CALCULATE_CT0_1  = 29;   //calculate INTT(c*t0)
    localparam VALIDITY_CHECK_2 = 30;   //compare infinityNorm(c*t0) >= GAMMA2 ? deny : accept
    localparam MAKE_HINT        = 31;   //calculate vector hint h
    localparam VALIDITY_CHECK_3 = 32;   //compare (number of 1's in h) > OMEGA ? deny : accept
    localparam SIG_ENCODE_Z     = 33;
    localparam SIG_ENCODE_H     = 34;
`ifdef DECODE_SECRET_KEY
    localparam SK_DECODE_RHO    = 35;
    localparam SK_DECODE_K      = 36;
    localparam SK_DECODE_TR     = 37;
    localparam SK_DECODE_S      = 38;
    localparam SK_DECODE_T0     = 39;
    localparam EXPAND_A         = 40;

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
    reg  [15 : 0]               expandMask_mu;
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
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_Y_OFFSET(RHO_Y_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .VECTOR_Y_BASE_OFFSET(VECTOR_Y_BASE_OFFSET)
    ) expandMask (.clk(clk),  .rst(rst),
        .start(expandMask_start),
        .done(expandMask_done),
        .rho(expandMask_rho),
        .mu(expandMask_mu),
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
    reg 
    localparam HIGH_BITS_LEN = $clog2((Q-1)/(2*GAMMA2)-1);
    localparam LOW_BITS_LEN  = COEFF_WIDTH - HIGH_BITS_LEN;
    //MU_squeezE
    localparam MU_SIZE = 64*8;
    localparam MU_END_OFFSET = MU_BASE_OFFSET + MU_SIZE / WORD_WIDTH;
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
            if      (w <= 1 *GAMMA2) HighBits = 0;
            else if (w <= 3 *GAMMA2) HighBits = 1;
            else if (w <= 5 *GAMMA2) HighBits = 2;
            else if (w <= 7 *GAMMA2) HighBits = 3;
            else if (w <= 9 *GAMMA2) HighBits = 4;
            else if (w <= 11*GAMMA2) HighBits = 5;
            else if (w <= 13*GAMMA2) HighBits = 6;
            else if (w <= 15*GAMMA2) HighBits = 7;
            else if (w <= 17*GAMMA2) HighBits = 8;
            else if (w <= 19*GAMMA2) HighBits = 9;
            else if (w <= 21*GAMMA2) HighBits = 10;
            else if (w <= 23*GAMMA2) HighBits = 11;
            else if (w <= 25*GAMMA2) HighBits = 12;
            else if (w <= 27*GAMMA2) HighBits = 13;
            else if (w <= 29*GAMMA2) HighBits = 14;
            else if (w <= 31*GAMMA2) HighBits = 15;
            else                     HighBits = 0;
        end
    endfunction

    function [LOW_BITS_LEN-1 : 0] LowBits; //component-wise of step 21
        input [COEFF_WIDTH-1 : 0] r;
        if      (r < 1 *GAMMA2) LowBits = r - 0  * 2 * GAMMA2;
        else if (r < 3 *GAMMA2) LowBits = r - 1  * 2 * GAMMA2;
        else if (r < 5 *GAMMA2) LowBits = r - 2  * 2 * GAMMA2;
        else if (r < 7 *GAMMA2) LowBits = r - 3  * 2 * GAMMA2;
        else if (r < 9 *GAMMA2) LowBits = r - 4  * 2 * GAMMA2;
        else if (r < 11*GAMMA2) LowBits = r - 5  * 2 * GAMMA2;
        else if (r < 13*GAMMA2) LowBits = r - 6  * 2 * GAMMA2;
        else if (r < 15*GAMMA2) LowBits = r - 7  * 2 * GAMMA2;
        else if (r < 17*GAMMA2) LowBits = r - 8  * 2 * GAMMA2;
        else if (r < 19*GAMMA2) LowBits = r - 9  * 2 * GAMMA2;
        else if (r < 21*GAMMA2) LowBits = r - 10 * 2 * GAMMA2;
        else if (r < 23*GAMMA2) LowBits = r - 11 * 2 * GAMMA2;
        else if (r < 25*GAMMA2) LowBits = r - 12 * 2 * GAMMA2;
        else if (r < 27*GAMMA2) LowBits = r - 13 * 2 * GAMMA2;
        else if (r < 29*GAMMA2) LowBits = r - 14 * 2 * GAMMA2;
        else if (r < 31*GAMMA2) LowBits = r - 15 * 2 * GAMMA2;
        else                    LowBits = r - 16 * 2 * GAMMA2;
    endfunction

    // Algorithm 39: Making hints, FIPS 204 page 41, slide 51
    // Computes hint bit indicating whether adding z to r alters the high bits of r.
    // Input : integers z, r in Z_q
    // Output: boolean
    function logic MakeHint
        input [COEFF_WIDTH-1 : 0] z, r;
        int tmp = (z + r) % Q;
        automatic [HIGH_BITS_LEN-1:] hb_z, hb_r;
        begin
            hb_r = HighBits(r);
            hb_z = HighBits(tmp);
            MakeHint = hb_r != hb_z;
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
            MU_ASBORB_TR: begin
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
            end
            CALCULATE_W_0: begin
            end
            CALCULATE_W_1: begin
            end
            CALCULATE_W_2: begin
            end
            HIGH_BITS_W: begin
            end
            HASH_COMMITMENT: begin
            end
            SAMPLE_IN_BALL: begin
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
            end
            LOW_BITS_0: begin
            end
            LOW_BITS_1: begin
            end
            VALIDITY_CHECK_1: begin
            end
            CALCULATE_CT0_0: begin
            end
            CALCULATE_CT0_1: begin
            end
            VALIDITY_CHECK_2: begin
            end
            MAKE_HINT: begin
            end
            VALIDITY_CHECK_3: begin
            end
            SIG_ENCODE_Z: begin
            end
            SIG_ENCODE_H: begin
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
                MU_ASBORB_TR: begin
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
                        out_ready <= 1;
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
                        shake256_last_len <= DATA_WIDTH;
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
                        shake256_rst <= 1;
                        shake256_cache_rst <= 1;
                        ram_addr_b_data <= RHO_PP_BASE_OFFSET;
                    end
                end
                EXPAND_MASK: begin
                    ram_we_a_data <= expandMask_ram_we;
                    ram_addr_a_data <= expandMask_ram_addr;
                    ram_din_a_data <= expandMask_ram_din;

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
                        //in_valid = 1;
                        expandMask_rho <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                    end else if(ram_addr_b_data < RHO_PP_END_OFFSET) begin
                        //in_valid = 1;
                        expandMask_rho <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                    end else if (expandMask_done) begin //setup for next state
                        shake256_rst <= 1;
                    end
                end
                CALCULATE_W_0: begin
                end
                CALCULATE_W_1: begin
                end
                CALCULATE_W_2: begin
                end
                HIGH_BITS_W: begin
                    //TODO
                end
                HASH_COMMITMENT: begin
                end
                SAMPLE_IN_BALL: begin
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
                end
                LOW_BITS_0: begin
                end
                LOW_BITS_1: begin
                end
                VALIDITY_CHECK_1: begin
                end
                CALCULATE_CT0_0: begin
                end
                CALCULATE_CT0_1: begin
                end
                VALIDITY_CHECK_2: begin
                end
                MAKE_HINT: begin
                end
                VALIDITY_CHECK_3: begin
                end
                SIG_ENCODE_Z: begin
                end
                SIG_ENCODE_H: begin
                end
            endcase
        end
    end
endmodule