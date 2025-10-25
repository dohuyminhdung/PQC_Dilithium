`timescale 1ns / 1ps
// Reference: Algorithm 8: Signature verification, FIPS 204 page 27, slide 37
// Internal function to verify a signature sigma for a formatted message M'
// Input:  Public key pk (length of 32 + 32*k*(bitlen(q-1)-d) bytes), formatted message M_, 
//         signature sigma (length of lambda/4 + 32*l*(1+bitlen(gamma1-1)) + omega + k)
// Output: True if the signature is valid, False otherwise

module Verify_internal #(
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
                                           //FIPS204, page 52, slide 62
    //raw data RAM parameters
    parameter int WORD_WIDTH = 64,      //FIXED, SHALL NOT MODIFY
    parameter int TOTAL_WORD = 4096,
    parameter int DATA_ADDR_WIDTH = $clog2(TOTAL_WORD),

    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int PUBLIC_KEY_SIZE = (32 + 32 * K * ($clog2(Q-1) - D)) * 8, //2592 bytes for ML-DSA87
    parameter int PUBLIC_KEY_END_OFFSET = PUBLIC_KEY_BASE_OFFSET + (PUBLIC_KEY_SIZE/WORD_WIDTH),

    parameter int RHO_BASE_OFFSET = PUBLIC_KEY_BASE_OFFSET,          //seed rho for expandA
    parameter int RHO_END_OFFSET = RHO_BASE_OFFSET + (32*8/WORD_WIDTH),

    parameter int VECTOR_T1_PACKED_BASE_OFFSET = RHO_END_OFFSET,    //unpack this to get vector t1
    parameter int VECTOR_T1_PACKED_END_OFFSET = PUBLIC_KEY_END_OFFSET,

    parameter int SIGNATURE_BASE_OFFSET = 0,    //c~, z mod_pm q, h
    parameter int SIGNATURE_SIZE = (LAMBDA/4 + L * 32 * (1 + GAMMA1) + OMEGA + K) * 8,
    parameter int SIGNATURE_END_OFFSET = SIGNATURE_BASE_OFFSET + (SIGNATURE_SIZE/WORD_WIDTH),

    parameter int CHALLENGE_BASE_OFFSET = SIGNATURE_BASE_OFFSET,    //seed rho for SampleInBall
    parameter int CHALLENGE_END_OFFSET = CHALLENGE_BASE_OFFSET + (LAMBDA/4*8/WORD_WIDTH),

    parameter int VECTOR_Z_PACKED_BASE_OFFSET = CHALLENGE_END_OFFSET, //packed vector z from signature
    parameter int VECTOR_Z_PACKED_SIZE        = L * 32 * (1 + GAMMA1) * 8 / WORD_WIDTH,
    parameter int VECTOR_Z_PACKED_END_OFFSET  = VECTOR_Z_PACKED_BASE_OFFSET + VECTOR_Z_PACKED_SIZE, 

    parameter int VECTOR_H_PACKED_BASE_OFFSET = VECTOR_Z_PACKED_END_OFFSET,
    parameter int VECTOR_H_PACKED_END_OFFSET  = CHALLENGE_END_OFFSET,
    parameter int VECTOR_H_PACKED_K_WORD_OFFSET = VECTOR_H_PACKED_END_OFFSET-2, //the address first word that store last K bytes
    parameter int VECTOR_H_PACKED_K_BIT_OFFSET = 24, //(OMEGA*8)%WORD_WIDTH = address of first byte in the word that store last K bytes

    parameter int VECTOR_H_BASE_OFFSET = 0,  //vector h             from decoding signature
    parameter int VECTOR_H_TOTAL_WORD = K * N / WORD_WIDTH, //at verify scheme, use 1 bit per coeff for optimize memory and read/write overhead
    parameter int VECTOR_H_END_OFFSET = VECTOR_H_BASE_OFFSET + VECTOR_H_TOTAL_WORD, //total 32 block ram for hint bit vector

    parameter int TR_BASE_OFFSET = 0,            //tr is use for signing
    parameter int TR_END_OFFSET  = TR_BASE_OFFSET + (64*8/WORD_WIDTH),

    parameter int MU_BASE_OFFSET = 0,       //seed after hashing message in step 6
    parameter int MU_END_OFFSET = MU_BASE_OFFSET + (64*8/WORD_WIDTH),

    //NTT data RAM parameters
    parameter int COEFF_WIDTH = 24,         //FIXED, SHALL NOT MODIFY
    parameter int COEFF_PER_WORD = 4,       //FIXED, SHALL NOT MODIFY
    parameter int WORD_COEFF = COEFF_WIDTH * COEFF_PER_WORD,
    parameter int TOTAL_COEFF = 4096,
    parameter int NTT_ADDR_WIDTH = $clog2(TOTAL_COEFF),

    parameter int MATRIX_A_BASE_OFFSET = 0,     //matrixA           from expandA
    parameter int MATRIX_A_TOTAL_WORD = (K*L*N/COEFF_PER_WORD), 
    parameter int MATRIX_A_END_OFFSET = MATRIX_A_BASE_OFFSET + MATRIX_A_TOTAL_WORD,

    parameter int VECTOR_T1_BASE_OFFSET = 0,     //vector t1         from decoding public key   
    parameter int VECTOR_T1_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_T1_END_OFFSET = VECTOR_T1_BASE_OFFSET + VECTOR_T1_TOTAL_WORD,

    parameter int VECTOR_W_APPROX_BASE_OFFSET = 0,     //vector w'_approx from calculating w' = A*z - ct1*(2^d)
    parameter int VECTOR_W_APPROX_TOTAL_WORD = K * N / COEFF_PER_WORD,
    parameter int VECTOR_W_APPROX_END_OFFSET = VECTOR_W_APPROX_BASE_OFFSET + VECTOR_W_APPROX_TOTAL_WORD,

    parameter int VECTOR_C_BASE_OFFSET = 0,     //challenge vector  form NTT(SampleInBall)
    parameter int VECTOR_C_TOTAL_WORD = N / COEFF_PER_WORD,
    parameter int VECTOR_C_END_OFFSET = VECTOR_C_BASE_OFFSET + VECTOR_C_TOTAL_WORD,

    parameter int VECTOR_Z_BASE_OFFSET = 0,    //vector z           from decoding signature
    parameter int VECTOR_Z_TOTAL_WORD = L * N / COEFF_PER_WORD,
    parameter int VECTOR_Z_END_OFFSET = VECTOR_Z_BASE_OFFSET + VECTOR_Z_TOTAL_WORD,  
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
    output reg                      valid_signature,                    
    //real time communicating with PS for hashing message and getting public key and signature from signer
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
    reg [COEFF_WIDTH-1:0] infinityNorm_z;   //compare infinityNorm(z) < GAMMA1-BETA ? valid : invalid in step 13

    // FSM state encoding
    reg [4:0] state, next_state;
    localparam IDLE                     = 0;
    localparam TR_ABSORB_PK_RHO         = 1;    //absorb rho in pk in step 6
    localparam TR_ABSORB_PK_DECODE_T1   = 2;    //absorb vector t1 in pk in step 6 and get vector t1 from pk in step 1
    localparam TR_SQUEEZE               = 3;    //squeeze TR in step 6
    localparam MU_ASBORB_TR             = 4;    //absorb TR in step 7
    localparam MU_ABSORB_MSG            = 5;    //absorb message in step 7
    localparam MU_SQUEEZE               = 6;    //squeeze mu in step 7
    localparam SAMPLE_IN_BALL           = 7;    //get commitment hash c~ from signature in step 2 and calculate vector c from c~ in step 8
    localparam SIG_DECODE_Z             = 8;    //get response vector z from signature in step 2
    localparam SIG_DECODE_H_0           = 9;    //get hint vector from signature in step 2, check if malformed input in the last K bytes of y
    localparam SIG_DECODE_H_1           = 10;   //get hint vector from signature in step 2, reconstruct h[i]
    localparam SIG_DECODE_H_2           = 11;   //get hint vector from signature in step 2, read any leftover bytes in the first OMEGA bytes of y
    localparam VALIDITY_CHECK_0         = 12;   //compare infinityNorm(z) < GAMMA1-BETA ? valid : invalid in step 13
    localparam EXPAND_A                 = 13;   //generate matrix A in step 5
    localparam NTT_Z                    = 14;   //calculate ntt(z) in step 9
    localparam NTT_C                    = 15;   //calculate ntt(c) in step 9
    localparam CALCULATE_W_APPROX_0     = 16;   //calculate t1 * 2^d in step 9
    localparam CALCULATE_W_APPROX_1     = 17;   //calculate ntt(t1 * 2^d) in step 9
    localparam CALCULATE_W_APPROX_2     = 18;   //calculate A * ntt(z) in step 9
    localparam CALCULATE_W_APPROX_3     = 19;   //calculate ntt(c) * ntt(t1 * 2^d) in step 9
    localparam CALCULATE_W_APPROX_4     = 20;   //calculate A*ntt(z) - ntt(c)*ntt(t1*2^d) in step 9
    localparam CALCULATE_W_APPROX_5     = 21;   //calculate intt(A*ntt(z) - ntt(c)*ntt(t1*2^d)) in step 9, the apply UseHint in step 10
    localparam C_ABSORB_MU              = 22;   //absorb mu in step 12
    localparam C_ABSORB_W1              = 23;   //absorb w1Encode(w'1) in step 12
    localparam C_SQUEEZE                = 24;   //squeeze c'~ in step 12, then compare c~ == c'~ ? valid : invalid in step 13

    //ExpandA instance
    reg                     expandA_start;
    wire                    expandA_done;
    reg  [WORD_WIDTH-1:0]   expandA_rho;
    wire                        expandA_ram_we;
    wire [NTT_ADDR_WIDTH-1:0]   expandA_ram_addr;
    wire [WORD_COEFF-1:0]       expandA_ram_din;
    wire                            expandA_shake_rst;
    wire [DATA_IN_BITS-1:0]         expandA_shake_data_in;
    wire                            expandA_shake_in_valid;
    wire                            expandA_shake_in_last;
    wire [$clog2(DATA_IN_BITS):0]   expandA_shake_last_len; 
    wire                            expandA_shake_cache_rd;
    wire                            expandA_shake_cache_wr;
    wire                            expandA_shake_out_ready;
    reg  [DATA_OUT_BITS-1:0]        expandA_shake_data_out;
    reg                             expandA_shake_out_valid;
    reg                             expandA_shake_in_ready;
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
    reg [127:0] buffer;
    reg [7  :0] buffer_cnt;
    reg invalid_detected;
    //pk_decode_t1
    localparam T1_COEFF_LEN = 23 - D;
    localparam T1_COEFF_WORD_LEN = COEFF_PER_WORD * T1_COEFF_LEN;
    //sig_decode_z
    localparam Z_COEFF_LEN = GAMMA1 + 1;
    localparam Z_COEFF_WORD_LEN = COEFF_PER_WORD * Z_COEFF_LEN;
    //sig_decode_h
    reg [7:0]               hint_poly_last_idx[K];
    reg [$clog2(K):0]       hint_poly_cnt;
    reg                     hint_wr_flag;   //turn on this when need to write data to ram
    reg [$clog2(N):0]       hint_wr_level;  //64, 128, 192 or 256
    reg [$clog2(OMEGA)-1:0] hint_index;     //Index in algorithm 21
    reg [$clog2(OMEGA)-1:0] hint_first;     //First in algorithm 21
    reg [7:0]               hint_last_idx;  //buffer for y[Index-1] in step 9 in algorithm 21
    reg [$clog2(WORD_WIDTH):0]  hint_sig_cur_cnt;
    reg [WORD_WIDTH-1:0]        hint_sig_cur;//another buffer for tracking current hint :DD    
    //use_hint
    localparam HIGH_BITS_LEN = $clog2((Q-1)/(2*GAMMA2)-1);
    localparam W1_WORD_COEFF = HIGH_BITS_LEN * COEFF_PER_WORD;
    /* ==================== INTERNAL SIGNALS ==================== */

    /* ====================  OTHER FUNCTIONS ==================== */
    function [COEFF_WIDTH-1 : 0] BitUnpack_vector_z;
        input [GAMMA1 : 0] z;
        begin
            BitUnpack_vector_z = gamma1 - z;
        end
    endfunction

    function [COEFF_WIDTH-1:0] infinityNorm;
        input [Z_COEFF_WORD_LEN-1:0] z_word_coeff;
        input unsigned [COEFF_WIDTH-1:0] cur_infinityNorm;
        localparam HALF_Q = Q >> 1;

        int signed coeff[0:3];
        int unsigned abs_val[0:3];
        int unsigned max, max1, max2;
        begin
            for (int i = 0; i < 4; i = i + 1) begin
                coeff[i] = z_word_coeff[i * Z_COEFF_LEN +: Z_COEFF_LEN];
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

    // Algorithm 40: Using hints, FIPS 204 page 41, slide 51
    // Returns the high bits of r adjusted according to hint h
    // Input: boolean h, integer r in Z_q
    // Output: integer r1 in Z_q with 0 <= r1 <= (q-1)/(2*gamma2)
    function [HIGH_BITS_LEN-1 : 0] UseHint;
        input logic h;
        input [COEFF_WIDTH-1 : 0] r;
        begin
            if(h == 0) begin
                if     (r <= 1 *GAMMA2) UseHint = 0;
                else if(r <= 3 *GAMMA2) UseHint = 1;
                else if(r <= 5 *GAMMA2) UseHint = 2;
                else if(r <= 7 *GAMMA2) UseHint = 3;
                else if(r <= 9 *GAMMA2) UseHint = 4;
                else if(r <= 11*GAMMA2) UseHint = 5;
                else if(r <= 13*GAMMA2) UseHint = 6;
                else if(r <= 15*GAMMA2) UseHint = 7;
                else if(r <= 17*GAMMA2) UseHint = 8;
                else if(r <= 19*GAMMA2) UseHint = 9;
                else if(r <= 21*GAMMA2) UseHint = 10;
                else if(r <= 23*GAMMA2) UseHint = 11;
                else if(r <= 25*GAMMA2) UseHint = 12;
                else if(r <= 27*GAMMA2) UseHint = 13;
                else if(r <= 29*GAMMA2) UseHint = 14;
                else if(r <= 31*GAMMA2) UseHint = 15;
                else                    UseHint = 0;
            end else begin
                if     (r == 0)         UseHint = 15;
                else if(r <= 1 *GAMMA2) UseHint = 1;
                else if(r <= 2 *GAMMA2) UseHint = 0;
                else if(r <= 3 *GAMMA2) UseHint = 2;
                else if(r <= 4 *GAMMA2) UseHint = 1;
                else if(r <= 5 *GAMMA2) UseHint = 3;
                else if(r <= 6 *GAMMA2) UseHint = 2;
                else if(r <= 7 *GAMMA2) UseHint = 4;
                else if(r <= 8 *GAMMA2) UseHint = 3;
                else if(r <= 9 *GAMMA2) UseHint = 5;
                else if(r <= 10*GAMMA2) UseHint = 4;
                else if(r <= 11*GAMMA2) UseHint = 6;
                else if(r <= 12*GAMMA2) UseHint = 5;
                else if(r <= 13*GAMMA2) UseHint = 7;
                else if(r <= 14*GAMMA2) UseHint = 6;
                else if(r <= 15*GAMMA2) UseHint = 8;
                else if(r <= 16*GAMMA2) UseHint = 7;
                else if(r <= 17*GAMMA2) UseHint = 9;
                else if(r <= 18*GAMMA2) UseHint = 8;
                else if(r <= 19*GAMMA2) UseHint = 10;
                else if(r <= 20*GAMMA2) UseHint = 9;
                else if(r <= 21*GAMMA2) UseHint = 11;
                else if(r <= 22*GAMMA2) UseHint = 10;
                else if(r <= 23*GAMMA2) UseHint = 12;
                else if(r <= 24*GAMMA2) UseHint = 11;
                else if(r <= 25*GAMMA2) UseHint = 13;
                else if(r <= 26*GAMMA2) UseHint = 12;
                else if(r <= 27*GAMMA2) UseHint = 14;
                else if(r <= 28*GAMMA2) UseHint = 13;
                else if(r <= 29*GAMMA2) UseHint = 15;
                else if(r <= 30*GAMMA2) UseHint = 14;
                else if(r <= 31*GAMMA2) UseHint = 0;
                else                    UseHint = 15;
            end
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
                if(start)
                    next_state = TR_ABSORB_PK_RHO;
            end
            TR_ABSORB_PK_RHO: begin
                if(ram_addr_b_data >= RHO_END_OFFSET-1)
                    next_state = TR_ABSORB_PK_DECODE_T1;
            end
            TR_ABSORB_PK_DECODE_T1: begin
                if(ram_addr_a_ntt >= VECTOR_T1_END_OFFSET-1)
                    next_state = TR_SQUEEZE;
            end
            TR_SQUEEZE: begin
                if(ram_addr_a_data >= TR_END_OFFSET-1)
                    next_state = MU_ASBORB_TR;
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
                    next_state = SAMPLE_IN_BALL;
            end
            SAMPLE_IN_BALL: begin
                if(sampleInBall_done)
                    next_state = SIG_DECODE_Z;
            end
            SIG_DECODE_Z: begin
                if(ram_addr_a_data >= VECTOR_Z_PACKED_END_OFFSET)
                    next_state = SIG_DECODE_H_0;
            end
            SIG_DECODE_H_0: begin
                if(ram_addr_b_data >= VECTOR_H_PACKED_END_OFFSET) begin
                    //check if malformed input
                    for(int i = 0; i < K; i = i + 1) begin
                        if(hint_poly_last_idx[i] < 0 || hint_poly_last_idx[i] > OMEGA)
                            next_state = IDLE;
                    end
                end else
                    next_state = SIG_DECODE_H_1;
            end
            SIG_DECODE_H_1: begin
                if(invalid_detected)
                    next_state = IDLE;
                else if(hint_index >= hint_poly_last_idx[hint_poly_cnt]) begin
                    if(hint_poly_cnt >= K-1)
                        next_state = SIG_DECODE_H_2;
                end
            end
            SIG_DECODE_H_2: begin
                if(invalid_detected)
                    next_state = IDLE;
                else if(hint_index >= OMEGA-1)
                    next_state = VALIDITY_CHECK_0;
            end
            VALIDITY_CHECK_0: begin
                if(infinityNorm_z < (gamma1 - BETA))
                    next_state = EXPAND_A;
                else
                    next_state = IDLE;
            end
            EXPAND_A: begin
                if(expandA_done)
                    next_state = NTT_Z;
            end
            NTT_Z: begin
            end 
            NTT_C: begin
            end
            CALCULATE_W_APPROX_0: begin
            end
            CALCULATE_W_APPROX_1: begin
            end
            CALCULATE_W_APPROX_2: begin
            end
            CALCULATE_W_APPROX_3: begin
            end
            CALCULATE_W_APPROX_4: begin
            end
            CALCULATE_W_APPROX_5: begin
            end
            C_ABSORB_MU: begin
                if(ram_addr_b_data >= MU_END_OFFSET-1)
                    next_state = C_ABSORB_W1; 
            end
            C_ABSORB_W1: begin
                if(shake256_in_last)
                    next_state = C_SQUEEZE;
            end
            C_SQUEEZE: begin
                if(invalid_detected || (ram_addr_b_data >= CHALLENGE_END_OFFSET-1))
                    next_state = IDLE;
            end
        endcase
    end

    always @(posedge clk) begin
        if(rst) begin
            //TODO: Reset signals that shall reset
        end else begin
            case(state)
                IDLE: begin
                    //TODO: Reset signals that shall reset
                    done <= 0;
                    shake256_in_last <= 0;
                    invalid_detected <= 0;
                    if(start) begin //setup for next state
                        shake256_cache_rst <= 1;
                        shake256_rst <= 1;
                        shake256_in_last <= 0;
                        shake256_last_len <= WORD_WIDTH;
                    end
                end
                TR_ABSORB_PK_RHO: begin
                    if(shake256_rst) begin                          //at this clock, SHAKE begin to reset
                        //setup for absorb state
                        shake256_rst <= 0;
                        shake256_cache_rst <= 0;
                        shake256_cache_rd <= 0;
                        shake256_cache_wr <= 0;
                        shake256_out_ready <= 0;
                        ram_addr_b_data <= PUBLIC_KEY_BASE_OFFSET;  //update first reading address for this state
                    end else if(shake256_in_ready) begin
                        //absorb pk in shake
                        shake256_in_valid <= 1;
                        shake256_data_in <= ram_dout_b_data;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                        
                        if(ram_addr_b_data >= RHO_END_OFFSET-1) begin //setup for next state
                            buffer <= 0;
                            buffer_cnt <= 0;
                            ram_addr_a_ntt <= VECTOR_T1_BASE_OFFSET-1;
                        end
                    end
                end
                TR_ABSORB_PK_DECODE_T1: begin
                    ram_we_a_ntt    <= 0;
                    shake256_in_valid   <= 0;
                    shake256_in_last    <= 0;
                    shake256_out_ready  <= 0;
                    if(buffer_cnt >= T1_COEFF_WORD_LEN) begin
                        ram_we_a_ntt    <= 1;
                        ram_addr_a_ntt  <= ram_addr_a_ntt + 1;
                        ram_din_a_ntt   <= {    COEFF_WIDTH'(buffer[3*T1_COEFF_LEN +: T1_COEFF_LEN]),
                                                COEFF_WIDTH'(buffer[2*T1_COEFF_LEN +: T1_COEFF_LEN]),
                                                COEFF_WIDTH'(buffer[1*T1_COEFF_LEN +: T1_COEFF_LEN]),
                                                COEFF_WIDTH'(buffer[0*T1_COEFF_LEN +: T1_COEFF_LEN]) };
                        buffer <= buffer >> T1_COEFF_WORD_LEN;
                        buffer_cnt <= buffer_cnt - T1_COEFF_WORD_LEN;
                    end else if(shake256_in_ready) begin
                        //move to next public key block data
                        ram_addr_b_data <= ram_addr_b_data + 1;

                        //absorb pk in shake
                        shake256_in_valid <= 1;
                        shake256_data_in <= ram_dout_b_data;

                        //write public key to buffer of vector t1 decoder
                        buffer[buffer_cnt+:WORD_WIDTH] <= msg_block;
                        buffer_cnt <= buffer_cnt + WORD_WIDTH; 

                        if(ram_addr_b_data >= PUBLIC_KEY_END_OFFSET-1) begin //trigger in last and setup for next state
                            shake256_in_last <= 1;
                            shake256_last_len <= (PUBLIC_KEY_SIZE % DATA_IN_BITS);
                            shake256_out_ready <= 1;
                            ram_addr_a_data <= TR_BASE_OFFSET-1;
                        end
                    end
                end
                TR_SQUEEZE: begin
                    ram_we_a_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= shake256_data_out;
                    end
                    if(ram_addr_a_data >= TR_END_OFFSET - 1) begin //setup for next state
                        shake256_rst <= 0;
                        ram_addr_b_data <= TR_BASE_OFFSET-1;
                    end
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

                    if(sampleInBall_start) begin                        //at this clock, SHAKE begin to reset
                        sampleInBall_start <= 0;
                        shake256_rst <= 0;
                        ram_addr_a_data <= SIGNATURE_BASE_OFFSET; //CHALLENGE_BASE_OFFSET, setup first absorb block of rho
                    end else if(ram_addr_a_data < CHALLENGE_END_OFFSET) begin
                        // in_valid <= 1;
                        sampleInBall_rho <= ram_dout_a_data;             //feed next block data of rho'
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if (sampleInBall_done) begin                //wait done and setup for next state
                        // buffer <= 0;
                        // buffer_cnt <= 0;
                        ram_addr_a_ntt <= VECTOR_Z_BASE_OFFSET - 1;
                        // ram_addr_a_data <= VECTOR_Z_PACKED_BASE_OFFSET;
                    end
                end
                SIG_DECODE_Z: begin
                    ram_we_a_ntt <= 0;
                    if(buffer_cnt >= Z_COEFF_WORD_LEN) begin
                        ram_we_a_ntt <= 1;
                        ram_addr_a_ntt  <= ram_addr_a_ntt + 1;
                        ram_din_a_ntt   <= { BitUnpack_vector_z(buffer[3*Z_COEFF_LEN +: Z_COEFF_LEN]), 
                                             BitUnpack_vector_z(buffer[2*Z_COEFF_LEN +: Z_COEFF_LEN]),
                                             BitUnpack_vector_z(buffer[1*Z_COEFF_LEN +: Z_COEFF_LEN]),
                                             BitUnpack_vector_z(buffer[0*Z_COEFF_LEN +: Z_COEFF_LEN]) };
                        buffer <= buffer >> Z_COEFF_WORD_LEN;
                        buffer_cnt <= buffer_cnt - Z_COEFF_WORD_LEN;

                        infinityNorm_z <= infinityNorm(buffer[0+:Z_COEFF_WORD_LEN], infinityNorm_z);
                    end else begin
                        //move to next signature block data
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        //write packed z from signature to buffer
                        buffer[buffer_cnt+:WORD_WIDTH] <= ram_dout_a_data;
                        buffer_cnt <= buffer_cnt + WORD_WIDTH;
                    end
                    if(ram_addr_a_data >= VECTOR_Z_PACKED_END_OFFSET-1) begin //setup for next state
                        ram_addr_b_data <= VECTOR_H_PACKED_K_WORD_OFFSET;
                        for(int i = 0; i < K; i = i + 1) begin
                            hint_poly_last_idx[i] <= 0;
                        end
                    end
                end
                SIG_DECODE_H_0: begin
                    if(ram_addr_b_data >= VECTOR_H_PACKED_END_OFFSET) begin
                        //check if malformed input
                        for(int i = 0; i < K; i = i + 1) begin
                            if(hint_poly_last_idx[i] < 0 ||
                                hint_poly_last_idx[i] > OMEGA) begin //step 4 in algorithm 21: if y[OMEGA+i] < Index or y[OMEGA+i] > OMEGA then return invalid signature
                                    done <= 1;
                                    valid_signature <= 0;
                            end
                        end
                    end else if(ram_addr_b_data >= VECTOR_H_PACKED_END_OFFSET-1) begin
                        hint_poly_last_idx[3] <= ram_dout_b_data[0*8 +:8];
                        hint_poly_last_idx[4] <= ram_dout_b_data[1*8 +:8];
                        hint_poly_last_idx[5] <= ram_dout_b_data[2*8 +:8];
                        hint_poly_last_idx[6] <= ram_dout_b_data[3*8 +:8];
                        hint_poly_last_idx[7] <= ram_dout_b_data[4*8 +:8];
                        
                        //setup for next state
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_addr_b_data <= VECTOR_H_BASE_OFFSET-1;
                        ram_din_b_data <= 0;
                        buffer <= 0;
                        hint_poly_cnt <= 0;
                        hint_wr_flag <= 0;
                        hint_wr_level <= 64;
                        hint_index <= 0;    //step 2 in algorithm 21: Index = 0
                        hint_first <= 0;    //step 6 in algorithm 21 first loop: First = Index = 0
                        hint_sig_cur_cnt <= WORD_WIDTH;
                        hint_sig_cur <= ram_dout_a_data;
                    end else begin
                        hint_poly_last_idx[0] <= ram_dout_b_data[(VECTOR_H_PACKED_K_BIT_OFFSET + 0*8)+:8];
                        hint_poly_last_idx[1] <= ram_dout_b_data[(VECTOR_H_PACKED_K_BIT_OFFSET + 1*8)+:8];
                        hint_poly_last_idx[2] <= ram_dout_b_data[(VECTOR_H_PACKED_K_BIT_OFFSET + 2*8)+:8];
                        //setup for next state
                        ram_addr_b_data <= ram_addr_b_data + 1;
                        ram_addr_a_data <= VECTOR_H_PACKED_BASE_OFFSET;
                    end
                end
                SIG_DECODE_H_1: begin
                    hint_wr_flag <= 0;
                    ram_we_b_data <= 0;
                    if( (  (hint_last_idx > hint_wr_level) &&                        //y[Index-1] >= 64/128/192
                           (hint_index < hint_poly_last_idx[hint_poly_cnt])  ) ||    
                        (hint_index >= hint_poly_last_idx[hint_poly_cnt]  )  ) begin //Index >= y[OMEGA+i] 
                        ram_we_b_data <= 1; //write unpacked data to ram
                        ram_addr_b_data <= ram_addr_b_data + 1;
                        ram_din_b_data <= buffer[0+:WORD_WIDTH];
                        buffer[0+:WORD_WIDTH] <= 0; //next 64 coeff
                        hint_wr_level <= (hint_wr_level == 256) ? 64 : (hint_wr_level << 1);
                        // hint_wr_level <= (hint_wr_level << 1);
                        if(hint_index >= hint_poly_last_idx[hint_poly_cnt]) begin //i+=1 in step 3: for i from 0 to k-1
                            hint_poly_cnt <= hint_poly_cnt + 1;
                            hint_first <= hint_index;                             //step 6: First = Index
                            // hint_wr_level <= 64;
                        end
                    end else if(hint_sig_cur_cnt == 0) begin
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        hint_sig_cur_cnt <= WORD_WIDTH;
                        hint_sig_cur <= ram_dout_a_data;
                    end else if(hint_index < hint_poly_last_idx[hint_poly_cnt]) begin                   //step 7: while Index < y[OMEGA + i]
                        if((hint_index > hint_first) && (hint_last_idx >= hint_sig_cur[0+:8])) begin    //step 8,9,10,11: if(Index > First) and (y[Index-1] >= y[Index]) => invalid signature
                            invalid_detected <= 1;
                            valid_signature <= 0;
                            done <= 1;
                        end
                        ram_din_b_data[hint_sig_cur[0+:6]] <= 1;    //step 12: h[i][y[Index]] = 1, take 6 instead of 8 for (Index % 64)
                        hint_index <= hint_index + 1;               //step 13: Index = Index + 1
                        hint_last_idx <= hint_sig_cur[0+:8];        //buffer y[Index-1]
                        hint_sig_cur <= hint_sig_cur >> 8;          //setup for next y[Index]
                        hint_sig_cur_cnt <= hint_sig_cur_cnt - 8;   //setup for next y[Index]
                    end
                end
                SIG_DECODE_H_2: begin
                    if(hint_sig_cur_cnt == 0) begin
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        hint_sig_cur_cnt <= WORD_WIDTH;
                        hint_sig_cur <= ram_dout_a_data;
                    end else begin
                        if (hint_sig_cur[0+:8] != 0) begin          //step 17: if y[i] != 0 return invalid signature
                            invalid_detected <= 1;
                            valid_signature <= 0;
                            done <= 1;
                        end
                        hint_index <= hint_index + 1;               //i+=1 in step 16
                        hint_sig_cur <= hint_sig_cur >> 8;          //setup for next y[Index]
                        hint_sig_cur_cnt <= hint_sig_cur_cnt - 8;   //setup for next y[Index]
                    end
                end
                VALIDITY_CHECK_0: begin
                    if(infinityNorm_z < (gamma1 - BETA)) begin
                        //if valid, setup for next state
                        expandA_start <= 1;
                        shake128_cache_rst <= 1;
                        shake128_rst <= 1;
                    end else begin
                        //else, done here with invalid signature
                        done <= 1;
                        valid_signature <= 0;
                    end
                end
                EXPAND_A: begin
                    ram_we_a_ntt <= expandA_ram_we;
                    ram_addr_a_ntt <= expandA_ram_addr;
                    ram_din_a_ntt <= expandA_ram_din;

                    //For ExpandA's absorb state, may need refactor that this state feed rho instead of the module
                    shake128_rst <= expandA_shake_rst;
                    shake128_data_in <= expandA_shake_data_in;
                    shake128_in_valid <= expandA_shake_in_valid;
                    shake128_in_last <= expandA_shake_in_last;
                    shake128_last_len <= expandA_shake_last_len;
                    shake128_cache_rd <= expandA_shake_cache_rd;
                    shake128_cache_wr <= expandA_shake_cache_wr;
                    shake128_out_ready <= expandA_shake_out_ready;

                    expandA_shake_data_out <= shake128_data_out;
                    expandA_shake_out_valid <= shake128_out_valid;
                    expandA_shake_in_ready <= shake128_in_ready;

                    if(expandA_start) begin                 //at this clock, SHAKE begin to reset
                        expandA_start <= 0;
                        shake128_rst <= 0;
                        shake128_cache_rst <= 0;
                        ram_addr_a_data <= RHO_BASE_OFFSET; //setup first absorb block of rho 
                    end else if(ram_addr_a_data < RHO_END_OFFSET) begin
                        // in_valid <= 1;
                        expandA_rho <= ram_dout_a_data;     //feed next block data of rho
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if (expandA_done) begin        //wait done and setup for next state
                        //TODO: setup for next state calculating NTT(z)
                    end
                end
                NTT_Z: begin
                end 
                NTT_C: begin
                end
                CALCULATE_W_APPROX_0: begin
                end
                CALCULATE_W_APPROX_1: begin
                end
                CALCULATE_W_APPROX_2: begin
                end
                CALCULATE_W_APPROX_3: begin
                end
                CALCULATE_W_APPROX_4: begin
                end
                CALCULATE_W_APPROX_5: begin
                    //write calculate result from VECTOR_W_APPROX_BASE_OFFSET to VECTOR_W_APPROX_END_OFFSET
                    
                    //setup for next state
                    // if (/*calculate done*/) begin
                    //     shake256_rst <= 1;
                    //     ram_addr_b_data <= MU_BASE_OFFSET;
                    //     ram_addr_a_data <= VECTOR_H_BASE_OFFSET; //taking hint for UseHint, setup for C_ABSORB_W1
                    // end
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
                        ram_addr_b_ntt <= VECTOR_W_APPROX_BASE_OFFSET;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        hint_sig_cur_cnt <= WORD_WIDTH;
                        hint_sig_cur <= ram_dout_a_data;
                        buffer_cnt <= 0;
                        buffer <= 0;
                    end
                end
                C_ABSORB_W1: begin
                    shake256_in_valid <= 0;
                    if(shake256_in_ready && buffer_cnt >= DATA_IN_BITS) begin
                        shake256_in_valid <= 1;
                        shake256_data_in <= buffer[0+:DATA_IN_BITS];
                        buffer_cnt <= buffer_cnt - DATA_IN_BITS;
                        buffer <= buffer >> DATA_IN_BITS;
                    end else if(hint_sig_cur_cnt == 0) begin
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        hint_sig_cur_cnt <= WORD_WIDTH;
                        hint_sig_cur <= ram_dout_a_data;
                    end else if(buffer_cnt <= 128 - W1_WORD_COEFF) begin
                        buffer_cnt <= buffer_cnt + W1_WORD_COEFF;
                        buffer[buffer_cnt+:W1_WORD_COEFF] <= {  UseHint(hint_sig_cur[3], ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                UseHint(hint_sig_cur[2], ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                UseHint(hint_sig_cur[1], ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                UseHint(hint_sig_cur[0], ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                        hint_sig_cur_cnt <= hint_sig_cur_cnt - COEFF_PER_WORD;
                        hint_sig_cur <= hint_sig_cur >> COEFF_PER_WORD;
                    end

                    if(ram_addr_b_ntt >= VECTOR_W_APPROX_END_OFFSET-1) begin //setup for next state
                        //turn on last absorb block flag for shake256
                        shake256_in_last <= 1;
                        shake256_last_len <= DATA_IN_BITS;
                        shake256_out_ready <= 1;
                        //setup for next state
                        ram_addr_b_data <= CHALLENGE_BASE_OFFSET;
                    end
                end
                C_SQUEEZE: begin
                    shake256_in_last <= 0;
                    if(shake256_out_valid) begin
                        if (shake256_data_out != ram_dout_b_data) begin
                            invalid_detected <= 1;
                            valid_signature <= 0;
                            done <= 1;
                        end else begin
                            ram_addr_b_data <= ram_addr_b_data + 1;
                        end
                    end
                    if(ram_addr_b_data >= CHALLENGE_END_OFFSET-1) begin
                        valid_signature <= 1;
                        done <= 1;
                    end
                end           
            endcase
        end
    end
endmodule