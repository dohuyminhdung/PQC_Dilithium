`timescale 1ns / 1ps
// Algorithm 6: Key generation (see FIPS 204 page 23, slide 33)
// Generate a public - private key pair from a seed 𝜉 (xi)
// Input: a 32-byte random string xi
// Output: Public key pk, private key sk

module KeyGen_internal #(
    //ML-DSA87 parameters
    parameter int Q = 8380417,
    parameter int N = 256,
    parameter int K = 8,
    parameter int L = 7,
    parameter int ETA = 2,      //the bound for coefficients of secret vectors s1, s2
    parameter int D = 13,       //number of bits used for rounding during compression of polynomial coefficients.
    parameter int SEED_SIZE = 32 * 8, //XI_SIZE
    //raw data RAM parameters
    parameter int WORD_WIDTH = 64,
    parameter int TOTAL_WORD = 4096,
    parameter int DATA_ADDR_WIDTH = $clog2(TOTAL_WORD),
    parameter int RHO_BASE_OFFSET = 0,          //seed rho for expandA
    parameter int RHO_PRIME_BASE_OFFSET = 0,    //seed rho' for expandS
    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int PUBLIC_KEY_SIZE = (32 + 32 * K * ($clog2(q-1) - D)) * 8, //2592 bytes for ML-DSA87
    parameter int SECRET_KEY_BASE_OFFSET = 0,   //rho, K, tr, s1.encode, s2.encode, t0
    parameter int K_BASE_OFFSET = SECRET_KEY_BASE_OFFSET + (32*8/WORD_WIDTH),   //K is use for signing
    parameter int TR_BASE_OFFSET = K_BASE_OFFSET + (32*8/WORD_WIDTH)            //tr is use for signing
    //NTT data RAM parameters
    parameter int COEFF_WIDTH = 24,
    parameter int COEFF_PER_WORD = 4,
    parameter int WORD_COEFF = COEFF_WIDTH * COEFF_PER_WORD,
    parameter int TOTAL_COEFF = 4096,
    parameter int NTT_ADDR_WIDTH = $clog2(TOTAL_COEFF),
    parameter int MATRIX_A_BASE_OFFSET = 0,     //matrixA           from expandA 
    parameter int VECTOR_S_BASE_OFFSET = 0,     //vector s1, s2     from expandS
    parameter int VECTOR_S1_BASE_OFFSET = VECTOR_S_BASE_OFFSET,
    parameter int VECTOR_S2_BASE_OFFSET = VECTOR_S1_BASE_OFFSET + (L*N/COEFF_PER_WORD);
    parameter int VECTOR_T_BASE_OFFSET = 0,     //vector t          from calculating t = A*s1 + s2      
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
    input  wire [WORD_WIDTH-1:0]    xi,
    input  wire                     start,
    output reg                      done,
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
    // FSM state encoding
    localparam IDLE             = 5'd0;
    localparam ABSORB_XI        = 5'd1;
    localparam SQUEEZE_RHO      = 5'd2;
    localparam SQUEEZE_RHO_PRIME= 5'd3;
    localparam SQUEEZE_K        = 5'd4;
    localparam EXPAND_A         = 5'd5;
    localparam EXPAND_S         = 5'd6;
    //define more state in fsm if need
    //TODO
    localparam CALCULATE_T_0    = 5'd7;     //calculate NTT(s1)
    localparam CALCULATE_T_1    = 5'd8;     //calculate (A * s1)
    localparam CALCULATE_T_2    = 5'd9;     //calculate NTT(t) = (A * s1) + s2
    localparam CALCULATE_T_3    = 5'd10;    //calculate INTT(t)
    localparam PK_ENCODE_RHO    = 5'd11;
    localparam PK_ENCODE_T1     = 5'd12;
    localparam SK_ENCODE_RHO    = 5'd13;
    localparam SK_ENCODE_TR_0   = 5'd14;
    localparam SK_ENCODE_TR_1   = 5'd15;
    localparam SK_ENCODE_S      = 5'd16;
    localparam SK_ENCODE_T0     = 5'd17;
    reg  [4:0] state, next_state;

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

    //ExpandS instance
    reg                     expandS_start;
    wire                    expandS_done;
    reg  [WORD_WIDTH-1:0]   expandS_rho;
    wire                        expandS_ram_we;
    wire [NTT_ADDR_WIDTH-1:0]   expandS_ram_addr;  
    wire [WORD_COEFF-1:0]       expandS_ram_din;
    wire                            expandS_shake_rst; 
    wire  [DATA_IN_BITS-1:0]        expandS_shake_data_in;
    wire                            expandS_shake_in_valid;
    wire                            expandS_shake_in_last;
    wire [$clog2(DATA_IN_BITS) : 0] expandS_shake_last_len;
    wire                            expandS_shake_cache_rd;
    wire                            expandS_shake_cache_wr;
    wire                            expandS_shake_out_ready;
    reg [DATA_OUT_BITS-1:0]         expandS_shake_data_out;
    reg                             expandS_shake_out_valid;
    reg                             expandS_shake_in_ready;
    ExpandS #( .K(K), .L(L), .ETA(ETA), .COEFF_PER_WORD(COEFF_PER_WORD),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_PRIME_BASE_OFFSET(RHO_PRIME_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .VECTOR_S_BASE_OFFSET(VECTOR_S_BASE_OFFSET)
    ) expandS (.clk(clk),  .rst(rst),
        .start(expandS_start),
        .done(expandS_done),
        .rho(expandS_rho),
        .we_vector_s(expandS_ram_we),
        .addr_vector_s(expandS_ram_addr),
        .din_vector_s(expandS_ram_din),
        .absorb_next_poly(expandS_shake_rst),
        .shake_data_in(expandS_shake_data_in),
        .in_valid(expandS_shake_in_valid),
        .in_last(expandS_shake_in_last),
        .last_len(expandS_shake_last_len),
        .cache_rd(expandS_shake_cache_rd),
        .cache_wr(expandS_shake_cache_wr),
        .out_ready(expandS_shake_out_ready),
        .shake_data_out(expandS_shake_data_out),
        .out_valid(expandS_shake_out_valid),
        .in_ready(expandS_shake_in_ready)
    );

    /* ==================== INTERNAL SIGNALS ==================== */
    //absorb xi
    reg [$clog2(SEED_SIZE):0] feed_cnt;
    //squeze rho
    localparam SQUEEZE_RHO_BLOCK = 32*8 / DATA_IN_BITS;
    localparam RHO_END_OFFSET    = RHO_BASE_OFFSET + SQUEEZE_RHO_BLOCK; 
    //squeeze rho_prime
    localparam SQUEEZE_RHO_PRIME_BLOCK = 64*8 / DATA_IN_BITS;
    localparam RHO_PRIME_END_OFFSET    = RHO_PRIME_BASE_OFFSET + SQUEEZE_RHO_PRIME_BLOCK;
    //squueze K
    localparam SQUEEZE_K_BLOCK = 32*8 / DATA_IN_BITS;
    localparam K_END_OFFSET    = K_BASE_OFFSET + SQUEEZE_K_BLOCK;
    //expandA
    localparam EXPAND_A_RHO_BLOCK = RHO_BASE_OFFSET + 32*8 / DATA_WIDTH;
    //expandS
    localparam EXPAND_S_RHO_BLOCK = RHO_PRIME_BASE_OFFSET + 64*8 / DATA_WIDTH;
    localparam VECTOR_S_TOTAL_WORD = (K+L)*N/COEFF_PER_WORD;
    localparam VECTOR_S_END_OFFSET = VECTOR_S_BASE_OFFSET + VECTOR_S_TOTAL_WORD;
    localparam VECTOR_S1_END_OFFSET = VECTOR_S2_BASE_OFFSET;
    localparam VECTOR_S2_END_OFFSET = VECTOR_S_END_OFFSET;
    // pk_encode_rho
    reg pk_rho_encode_start; //init = 0
    //pk_encode_t1 + sk_encode_t0
    localparam VECTOR_T_TOTAL_WORD = K * N / COEFF_PER_WORD;
    localparam VECTOR_T_END_OFFSET = VECTOR_T_BASE_OFFSET + VECTOR_T_TOTAL_WORD;
    localparam T1_COEFF_WORD_LEN = 10 * COEFF_WIDTH; //refer OTHER FUNCTIONS to know why
    localparam T0_COEFF_WORD_LEN = 13 * COEFF_WIDTH; //refer OTHER FUNCTIONS to know why
    reg [112:0] t_buffer;       //112 = max(DATA_WIDTH + T1_COEFF_WORD_LEN - GCD(DATA_WIDTH, T1_COEFF_WORD_LEN), DATA_WIDTH + T0_COEFF_WORD_LEN - GCD(DATA_WIDTH, T0_COEFF_WORD_LEN))
    reg [6  :0] t_buffer_cnt;   //$clog2(112)
    //sk_encode_tr
    localparam PUBLIC_KEY_END_OFFSET = PUBLIC_KEY_BASE_OFFSET + (PUBLIC_KEY_SIZE/WORD_WIDTH);
    localparam TR_END_OFFSET         = TR_BASE_OFFSET + 64 * 8;
    //sk_encode_s
    localparam ETA_PACK_LEN = $clog2(ETA*2+1);
    localparam S_COEFF_WORD_LEN = ETA_PACK_LEN * COEFF_PER_WORD;
    reg [6 :0] s_buffer_cnt;
    reg [95:0] s_buffer;
    /* ==================== INTERNAL SIGNALS ==================== */

    /* ====================  OTHER FUNCTIONS ==================== */
    // Algorithm 35: Power-of-two rounding, FIPS 204 page 40, slide 50
    // Power2Round(r) = (r1, r0) such that r = r1*2^d + r0 mod q 
    // Input: integer r in Z_q              // Output: integer (r1, r0)
    //Calculating bit width for coeff in t1 for pkEncode:
    //Step 3: SimpleBitPack(polynomial t1[i], 2^(bitlen(q-1)-d)-1)
    //      = SimpleBitPack(    256 coeff   ,       1023         ) => 10 bit for each coeff
    function [9:0] Power2Round_t1;
        input [COEFF_WIDTH-1:0] r;
        logic [12:0] r0_raw;
        logic adjust;
        logic [9:0] r1_base;//22:13
        begin
            r0_raw  = r[12:0];
            r1_base = r[22:13];
            adjust = (r0_raw > 13'd4096); //2^(d-1)
            Power2Round_t1 = r1_base + adjust;
        end
    endfunction

    //Calculating bit width for coeff in t0 for skEncode: 23 - 10 = 13 :DD
    function [12:0] Power2Round_t0;
        input [COEFF_WIDTH-1:0] r;
        logic [12:0] r0_raw;
        logic adjust;
        begin
            r0_raw = r[12:0];
            adjust = (r0_raw > 13'd4096)
            Power2Round_t0 = adjust ? (r0_raw - 13'd8192) : r0_raw;
        end
    endfunction

    //Algorithm 17: Bit packing, FIPS 204 page 30, slide 40. FOR VECTOR_S ONLY
    //This function will encode a coeff in vector s1 or s2 into a bit string only
    //Input: a, b in integer and w is a polynomial in R_q with coefficients in [-a, b]
    //Output: A byte string of length 32 * bitlen(a + b)
    function [ETA_PACK_LEN-1:0] BitPack_vector_s;
        input [COEFF_WIDTH-1:0] s;
        begin
            case(s)
                COEFF_WIDTH'd8380415:   BitPack_vector_s = ETA_PACK_LEN'(ETA + 2);  //-2
                COEFF_WIDTH'd8380416:   BitPack_vector_s = ETA_PACK_LEN'(ETA + 1);  //-1
                COEFF_WIDTH'd0:         BitPack_vector_s = ETA_PACK_LEN'(ETA);      //0
                COEFF_WIDTH'd1:         BitPack_vector_s = ETA_PACK_LEN'(ETA - 1);  //1
                COEFF_WIDTH'd2:         BitPack_vector_s = ETA_PACK_LEN'(ETA - 2);  //2
            endcase
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
                    next_state = ABSORB_XI;
            end
            ABSORB_XI: begin
                if (in_ready && (feed_cnt >= SEED_SIZE)) 
                    next_state = SQUEEZE_RHO;
            end
            SQUEEZE_RHO: begin
                if (ram_addr_a_data >= RHO_END_OFFSET-1)
                    next_state = SQUEEZE_RHO_PRIME;
            end
            SQUEEZE_RHO_PRIME: begin
                if (ram_addr_b_data >= RHO_PRIME_END_OFFSET-1)
                    next_state = SQUEEZE_K;
            end
            SQUEEZE_K: begin
                if (ram_addr_a_data >= K_END_OFFSET-1)
                    next_state = EXPAND_A;
            end
            EXPAND_A: begin
                if(expandA_done)
                    next_state = EXPAND_S;
            end
            EXPAND_S: begin
                if(expandS_done)
                    next_state = CALCULATE_T_0;
            end
            CALCULATE_T_0: begin
                //TODO
                if(/* conditon done calculating NTT(s1) */)
                    next_state = CALCULATE_T_1;
            end
            CALCULATE_T_1: begin
                //TODO
                if(/* condition done calculating (A * s1) */)
                    next_state = CALCULATE_T_2;
            end
            CALCULATE_T_2: begin
                //TODO
                if(/* condition done calculating NTT(t) = (A * s1) + s2 */)
                    next_state = CALCULATE_T_3;
            end
            CALCULATE_T_3: begin
                //TODO
                if(/* condition done calculating INTT(t) */)
                    next_state = PK_ENCODE_RHO;
            end
            PK_ENCODE_RHO: begin
                if(ram_addr_b_data >= RHO_END_OFFSET-1)
                    next_state = PK_ENCODE_T1; 
            end
            PK_ENCODE_T1: begin
                if(ram_addr_b_ntt >= VECTOR_T_END_OFFSET)
                    next_state = SK_ENCODE_RHO;
            end
            SK_ENCODE_RHO: begin
                if(ram_addr_b_data >= RHO_END_OFFSET-1)
                    next_state = SK_ENCODE_TR_0; 
            end
            SK_ENCODE_TR_0: begin
                if(ram_addr_b_data >= PUBLIC_KEY_END_OFFSET-1)
                    next_state = SK_ENCODE_TR_1; 
            end
            SK_ENCODE_TR_1: begin
                if(ram_addr_a_data >= TR_END_OFFSET-1)
                    next_state = SK_ENCODE_S;
            end
            SK_ENCODE_S: begin
                if(ram_addr_b_ntt >= VECTOR_S_END_OFFSET)
                    next_state = SK_ENCODE_T0;
            end
            SK_ENCODE_T0: begin
                if(ram_addr_b_ntt >= VECTOR_T_END_OFFSET)
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
                    //TODO: Reset signals that shall reset
                    if(start) begin 
                        shake128_rst <= 1;
                        shake256_rst <= 1;
                    end
                end
                ABSORB_XI: begin
                    if(shake256_in_ready) begin
                        shake256_in_valid <= 1;
                        if(feed_cnt + DATA_IN_BITS < SEED_SIZE) begin
                            shake256_data_in <= xi;
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                            shake256_in_last <= 0;
                        end else begin
                            shake256_data_in <= { (DATA_IN_BITS-16)'(0), 8'(K), 8'(L) };
                            feed_cnt <= 0;
                            shake256_in_last <= 1;
                            ram_addr_a_data <= RHO_BASE_OFFSET - 1; //setup for next state
                        end 
                    end else begin
                        shake256_out_ready <= 0;
                        shake128_rst <= 0;
                        shake256_rst <= 0;
                    end
                end
                SQUEEZE_RHO: begin
                    ram_we_a_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_din_a_data <= shake256_data_out;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end
                    ram_addr_b_data <= RHO_PRIME_BASE_OFFSET - 1; //setup for next state
                end
                SQUEEZE_RHO_PRIME: begin
                    ram_we_b_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_b_data <= 1;
                        ram_din_b_data <= shake256_data_out;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                    end
                    ram_addr_a_data <= K_BASE_OFFSET - 1;
                end
                SQUEEZE_K: begin
                    ram_we_a_data <= 0;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_din_a_data <= shake256_data_out;
                        ram_addr_a_data <= ram_addr_a_data + 1;

                        if(ram_addr_a_data >= K_END_OFFSET-1) begin //setup for next state
                            expandA_start <= 1;
                            shake128_cache_rst <= 1;
                            shake128_rst <= 1;
                        end
                    end
                end
                EXPAND_A: begin
                    ram_we_a_data <= expandA_ram_we;
                    ram_addr_a_data <= expandA_ram_addr;
                    ram_din_a_data <= expandA_ram_din;

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
                        // shake128_cache_rst <= 0;
                        shake128_rst <= 0;
                        ram_addr_a_data <= RHO_BASE_OFFSET; //setup first absorb block of rho
                    end else if(shake128_cache_rst) begin   //at this clock, SHAKE is IDLE, ready data to feed for ABSORB state
                                                            //check cache_rst as a handshake/lookup SHAKE current state
                        shake128_cache_rst <= 0;
                        // in_valid <= 1;
                        expandA_rho <= ram_dout_a_data;     //ready first block of rho for expandA
                        ram_addr_a_data <= ram_addr_a_data + 1; 
                    end else if(ram_addr_a_data < EXPAND_A_RHO_BLOCK) begin
                        // in_valid <= 1;
                        expandA_rho <= ram_dout_a_data;     //feed next block data of rho
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if (expandA_done) begin        //wait done and setup for next ExpandS state
                            expandS_start <= 1;
                            shake256_cache_rst <= 1;
                            shake256_rst <= 1;
                    end
                end
                EXPAND_S: begin
                    ram_we_a_data <= expandS_ram_we;
                    ram_addr_a_data <= expandS_ram_addr;
                    ram_din_a_data <= expandS_ram_din;

                    //For ExpandS's absorb state, may need refactor that this state feed rho instead of the module
                    shake256_rst <= expandS_shake_rst;
                    shake256_data_in <= expandS_shake_data_in;
                    shake256_in_valid <= expandS_shake_in_valid;
                    shake256_in_last <= expandS_shake_in_last;
                    shake256_last_len <= expandS_shake_last_len;
                    shake256_cache_rd <= expandS_shake_cache_rd;
                    shake256_cache_wr <= expandS_shake_cache_wr;
                    shake256_out_ready <= expandS_shake_out_ready;

                    expandS_shake_data_out <= shake256_data_out;
                    expandS_shake_out_valid <= shake256_out_valid;
                    expandS_shake_in_ready <= shake256_in_ready;

                    if(expandS_start) begin                             //at this clock, SHAKE begin to reset
                        expandS_start <= 0;
                        // shake256_cache_rst <= 0;
                        shake256_rst <= 0;
                        ram_addr_a_data <= RHO_PRIME_BASE_OFFSET;       //setup first absorb block of rho
                    end else if(shake256_cache_rst) begin               //at this clock, SHAKE is IDLE, ready data to feed for ABSORB state
                                                                        //check cache_rst as a handshake/lookup SHAKE current state
                        shake256_cache_rst <= 0;
                        // in_valid <= 1;
                        expandA_rho <= ram_dout_a_data;                 //ready first block of rho for expandS
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if(ram_addr_a_data < EXPAND_S_RHO_BLOCK) begin
                        // in_valid <= 1;
                        expandS_rho <= ram_dout_a_data;             //feed next block data of rho'
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end else if (expandS_done) begin                //wait done and setup for next CALCULATE_VECOTR_T state
                        //TODO: setup for next state CALCULATE_T_0 
                    end
                end
                CALCULATE_T_0: begin
                    //TODO: calculate NTT(s1)
                end
                CALCULATE_T_1: begin
                    //TODO: calculate (A * s1)
                end
                CALCULATE_T_2: begin
                    //TODO: calculate NTT(t) = (A * s1) + s2
                end
                CALCULATE_T_3: begin
                    //TODO: calculate INTT(t)
                    
//if can detected, setup for next KEY_ENCODE_RHO state
                    if(/* last clk of this state detected */) begin 
                        ram_addr_a_data <= PUBLIC_KEY_BASE_OFFSET-1;    //writing port
                        ram_addr_b_data <= RHO_BASE_OFFSET;             //reading port
                    end
                end
                PK_ENCODE_RHO: begin
//if can not setup in last state, assgin start writing address here
                    if(!pk_rho_encode_start) begin
                        pk_rho_encode_start <= 1
                        ram_addr_a_data <= PUBLIC_KEY_BASE_OFFSET-1;    //writing port
                        ram_addr_b_data <= RHO_BASE_OFFSET;             //reading port
                    end else begin
                        //write rho to public key
                        ram_we_a_data <= 1;                     //enable write
                        ram_din_a_data <= ram_dout_b_data;      //update writing data = reading data
                        ram_addr_a_data <= ram_addr_a_data + 1; //update writing address for next clock
                        ram_addr_b_data <= ram_addr_b_data + 1; //update reading address for next clock
                    end
                    if (ram_addr_b_data >= RHO_END_OFFSET-1) begin  //setup for next encode t1 for public key state
                        ram_addr_b_ntt <= VECTOR_T_BASE_OFFSET;     //reading port
                        t_buffer_cnt <= 0;                         //counting current index of t1 buffer
                        t_buffer <= 0;                             //buffer for writing data to RAM
                    end
                end
                PK_ENCODE_T1: begin
                    if(t_buffer_cnt >= DATA_WIDTH) begin
                        //write t1 to public key 
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= t_buffer[0+:DATA_WIDTH];
                        t_buffer_cnt <= t_buffer_cnt - DATA_WIDTH;
                        t_buffer <= t_buffer >> DATA_WIDTH;
                    end else if(!(ram_addr_b_ntt >= VECTOR_T_END_OFFSET)) begin
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                        t_buffer_cnt <= t_buffer_cnt + 40;
                        t_buffer[t_buffer_cnt+:40] <= {    Power2Round_t1(ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t1(ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t1(ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t1(ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
                    end else begin
                        ram_addr_a_data <= SECRET_KEY_BASE_OFFSET-1;    //writing port
                        ram_addr_b_data <= RHO_BASE_OFFSET;             //reading port
                    end
                end
                SK_ENCODE_RHO: begin
                    //write rho to private key
                    ram_we_a_data <= 1;                             //enable write
                    ram_din_a_data <= ram_dout_b_data;              //update writing data = reading data
                    ram_addr_a_data <= ram_addr_a_data + 1;         //update writing address for next clock
                    ram_addr_b_data <= ram_addr_b_data + 1;        //update reading address for next clock
                    
                    if (ram_addr_b_data >= RHO_END_OFFSET-1)  begin  
                        //setup for next encode tr for secret key state
                        shake256_cache_rst <= 1;
                        shake256_rst <= 1;
                    end
                end
                SK_ENCODE_TR_0: begin   //absorbing state
                    if(shake256_rst) begin                          //at this clock, SHAKE begin to reset
                        //setup for absorb state
                        shake256_rst <= 0;
                        shake256_cache_rd <= 0;
                        shake256_cache_wr <= 0;
                        shake256_out_ready <= 0;
                        ram_addr_b_data <= PUBLIC_KEY_BASE_OFFSET;  //update first reading address for this state
                    end else if(shake256_cache_rst) begin           //at this clock, SHAKE is IDLE
                        shake256_cache_rst <= 0;
                    end else if(shake256_in_ready) begin
                        shake256_in_valid <= 1;
                        shake256_data_in <= ram_dout_b_data;
                        shake256_last_len <= WORD_WIDTH;
                        ram_addr_b_data <= ram_addr_b_data + 1;
                        shake256_in_last <= (ram_addr_b_data >= PUBLIC_KEY_END_OFFSET-1) ? 1 : 0;
                    end 
                end
                SK_ENCODE_TR_1: begin   //squeezing state
                    shake256_out_ready <= 1;
                    shake256_in_valid <= 0;
                    shake256_in_last <= 0;
                    ram_we_a_data <= 0;
                    ram_addr_a_data <= TR_BASE_OFFSET - 1;
                    if(shake256_out_valid) begin
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <=  shake256_data_out;
                    end
                    //setup for next state
                    ram_addr_b_ntt <= VECTOR_S_BASE_OFFSET; //reading port
                end
                SK_ENCODE_S: begin
                    if(s_buffer_cnt >= DATA_WIDTH) begin
                        //write s1 and s2 to secret key
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= s_buffer[0+:DATA_WIDTH];
                        s_buffer_cnt <= s_buffer_cnt - DATA_WIDTH;
                        s_buffer <= s_buffer >> DATA_WIDTH;
                    end else if (!(ram_addr_b_ntt >= VECTOR_S_END_OFFSET)) begin
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                        s_buffer_cnt <= s_buffer_cnt + S_COEFF_WORD_LEN;
                        s_buffer[s_buffer_cnt+:S_COEFF_WORD_LEN] <= {   BitPack_vector_s(ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                        BitPack_vector_s(ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                        BitPack_vector_s(ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                                        BitPack_vector_s(ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
                    end else begin                              //setup for next encode t0 for secret key state
                        ram_addr_b_ntt <= VECTOR_T_BASE_OFFSET; //reading port
                        t_buffer_cnt <= 0;                     ///counting current index of t0 buffer
                        t_buffer <= 0;                         //buffer for writing data to RAM
                    end
                end
                SK_ENCODE_T0: begin
                    if(t_buffer_cnt >= DATA_WIDTH) begin
                        //write t0 to private key
                        ram_we_a_data <= 1;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                        ram_din_a_data <= t_buffer[0+:DATA_WIDTH];
                        t_buffer_cnt <= t_buffer_cnt - DATA_WIDTH;
                        t_buffer <= t_buffer >> DATA_WIDTH; 
                    end else if(!(ram_addr_b_ntt >= VECTOR_T_END_OFFSET)) begin
                        ram_addr_b_ntt <= ram_addr_b_ntt + 1;
                        t_buffer_cnt <= t_buffer_cnt + 52;
                        t_buffer[t_buffer_cnt+:52] <= {   Power2Round_t0(ram_dout_b_ntt[3 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t0(ram_dout_b_ntt[2 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t0(ram_dout_b_ntt[1 * COEFF_WIDTH +: COEFF_WIDTH]),
                                                            Power2Round_t0(ram_dout_b_ntt[0 * COEFF_WIDTH +: COEFF_WIDTH]) };
                    end else begin
                        done <= 1;
                    end
                end
            endcase
        end
    end
endmodule