`timescale 1ns / 1ps
// Algorithm 6: Key generation (see FIPS 204 page 23, slide 33)
// Generate a public - private key pair from a seed
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
    parameter int TOTAL_WORD = 2048,
    parameter int DATA_ADDR_WIDTH = $clog2(TOTAL_WORD),
    parameter int RHO_BASE_OFFSET = 0,          //seed rho for expandA
    parameter int RHO_PRIME_BASE_OFFSET = 0,    //seed rho' for expandS
    parameter int K_BASE_OFFSET = 0,            //seed K for signing
    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int SECRET_KEY_BASE_OFFSET = 0,   //rho, K, tr, s1.encode, s2.encode, t0
    //NTT data RAM parameters
    parameter int COEFF_WIDTH = 24,
    parameter int COEFF_PER_WORD = 4,
    parameter int WORD_COEFF = COEFF_WIDTH * COEFF_PER_WORD,
    parameter int TOTAL_COEFF = 2048,
    parameter int NTT_ADDR_WIDTH = $clog2(TOTAL_COEFF),
    parameter int MATRIX_A_BASE_OFFSET = 0,     //matrixA 
    parameter int VECTOR_S_BASE_OFFSET = 0,     //vector s1, s2
    parameter int VECTOR_T_BASE_OFFSET = 0,     //public key t
    //SHAKE parameters
    parameter int DATA_IN_BITS = WORD_WIDTH,
    parameter int DATA_OUT_BITS = WORD_WIDTH
)(
    //internal signals
    input  wire                     clk,
    input  wire                     rst,
    input  wire [SEED_SIZE-1:0]     xi,
    input  wire                     start,
    output reg                      done
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
    input  wire [WORD_COEFF-1:0]        ram_dout_a_ntt,
    //SHAKE signals
    output reg                              shake_rst,
    output reg  [DATA_IN_BITS-1:0]          shake_data_in,
    input  wire                             shake_in_valid, 
    input  wire                             shake_in_last, 
    input  wire [$clog2(DATA_IN_BITS):0]    shake_last_len,
    output reg                              cache_rst,
    output reg                              cache_rd,
    output reg                              cache_wr,
    input  wire                             shake_out_ready,   
    output reg  [DATA_OUT_BITS-1:0]         shake_data_out,
    output reg                              shake_out_valid,
    output reg                              shake_in_ready
);
    // FSM state encoding
    localparam IDLE             = 5'd0;
    localparam ABSORB_XI        = 5'd1;
    localparam SQUEEZE_RHO      = 5'd2;
    localparam SQUEEZE_RHO_PRIME= 5'd3;
    localparam SQUEEZE_K        = 5'd4;
    localparam EXPAND_A         = 5'd5;
    localparam EXPAND_S         = 5'd6;
    localparam CALCULATE_T_0    = 5'd7;    
    localparam CALCULATE_T_1    = 5'd8;
    localparam CALCULATE_T_2    = 5'd9;
    localparam CALCULATE_T_3    = 5'd10;
    localparam PK_ENCODE_RHO    = 5'd11;
    localparam PK_ENCODE_T1     = 5'd12;
    localparam SK_ENCODE_RHO    = 5'd13;
    localparam SK_ENCODE_K      = 5'd14;
    localparam SK_ENCODE_TR     = 5'd15;
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
    wire [$clog2(DATA_IN_BITS):0]   expandA_shake_in_last_len, 
    wire                            expandA_shake_cache_rd,
    wire                            expandA_shake_cache_wr,
    wire                            expandA_shake_out_ready,
    reg  [DATA_OUT_BITS-1:0]        expandA_shake_data_out,
    reg                             expandA_shake_out_valid,
    reg                             expandA_shake_in_ready
    ExpandA #( .K(K), .L(L),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_BASE_OFFSET(RHO_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .MATRIX_A_BASE_OFFSET(MATRIX_A_BASE_OFFSET)
    ) expandA (
        .clk(clk),  .rst(rst),  .start(expandA_start),
        .done(expandA_done),    .rho(expandA_rho),
        .we_matA(expandA_ram_we),
        .addr_matA(expandA_ram_addr),
        .din_matA(expandA_ram_din),
        .absorb_next_poly(expandA_shake_rst),
        .shake_data_in(expandA_shake_data_in),
        .in_valid(expandA_shake_in_valid),
        .in_last(expandA_shake_in_last),
        .last_len(expandA_shake_in_last_len),
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
    wire                                    expandS_shake_rst; 
    wire  [DATA_IN_BITS-1:0]                expandS_shake_data_in;
    wire                                    expandS_shake_in_valid;
    wire                                    expandS_shake_in_last;
    wire [$clog2(DATA_IN_BITS) : 0]         expandS_shake_last_len;
    wire                                    expandS_shake_cache_rd;
    wire                                    expandS_shake_cache_wr;
    wire                                    expandS_shake_out_ready;
    reg [DATA_OUT_BITS-1:0]                 expandS_shake_data_out;
    reg                                     expandS_shake_out_valid;
    reg                                     expandS_shake_in_ready;
    ExpandS #( .K(K), .L(L), .ETA(ETA),
        .WORD_WIDTH(WORD_WIDTH),    .TOTAL_WORD(TOTAL_WORD),    .RHO_PRIME_BASE_OFFSET(RHO_PRIME_BASE_OFFSET),
        .COEFF_WIDTH(COEFF_WIDTH),  .TOTAL_COEFF(TOTAL_COEFF),  .VECTOR_S_BASE_OFFSET(VECTOR_S_BASE_OFFSET)
    ) expandS (
        .clk(clk),  .rst(rst),  .start(expandS_start),
        .done(expandS_done),    .rho(expandS_rho),
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

    // Algorithm 35: Power-of-two rounding, FIPS 204 page 40, slide 50
    // Power2Round(r) = (r1, r0) such that r = r1*2^d + r0 mod q 
    // Input: integer r in Z_q
    // Output: integer (r1, r0)
    
    //Calculating bit width for coeff in t1 for pkEncode:
    //Step 3: SimpleBitPack(polynomial t1[i], 2^(bitlen(q-1)-d)-1)
    //      = SimpleBitPack(256 coeff       , 1023) => 10 bit for each coeff
    //May use macro here but it just make code look messy and it is not necessary
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

    //absorb xi
    reg [$clog2(SEED_SIZE) : 0] feed_cnt;

    reg [$clog2(64*8) : 0]      squeeze_cnt;
    //squeze rho
    localparam SQUEEZE_RHO_BLOCK = 32*8 / DATA_IN_BITS;
    //squeeze rho_prime
    localparam SQUEEZE_RHO_PRIME_BLOCK = 64*8 / DATA_IN_BITS;
    //squueze K
    localparam SQUEEZE_K_BLOCK = 32*8 / DATA_IN_BITS;

    //expandA
    localparam EXPAND_A_RHO_BLOCK = 32*8 / DATA_WIDTH;
    reg [$clog2(EXPAND_A_RHO_BLOCK):0] expandA_rho_block;
    //expandS
    localparam EXPAND_S_RHO_BLOCK = 64*8 / DATA_WIDTH;
    reg [$clog2(EXPAND_S_RHO_BLOCK):0] expandS_rho_block;

    always @(posedge clk) begin
        if (rst) begin
            state <= IDLE;
        end else begin
            state <= next_state;
        end
    end

    always @* begin
        next_state = state
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
                if (squeeze_cnt >= SQUEEZE_RHO_BLOCK-1) 
                    next_state = SQUEEZE_RHO_PRIME;
            end
            SQUEEZE_RHO_PRIME: begin
                if (squeeze_cnt >= SQUEEZE_RHO_PRIME_BLOCK-1)
                    next_state = SQUEEZE_K;
            end
            SQUEEZE_K: begin
                if (squeeze_cnt >= SQUEEZE_K_BLOCK-1)
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

            end
            CALCULATE_T_1: begin

            end
            CALCULATE_T_2: begin

            end
            CALCULATE_T_3: begin

            end
            PK_ENCODE_RHO: begin

            end
            PK_ENCODE_T1: begin

            end
            SK_ENCODE_RHO: begin

            end
            SK_ENCODE_K: begin

            end
            SK_ENCODE_TR: begin

            end
            SK_ENCODE_S: begin

            end
            SK_ENCODE_T0: begin

            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
        end else begin
            case(state)
                IDLE: begin
                    if(start)
                        shake_rst <= 1;
                end
                ABSORB_XI: begin
                    shake_out_ready <= 0;
                    if(shake_in_ready) begin
                        shake_in_valid <= 1;
                        if(feed_cnt + DATA_IN_BITS < SEED_SIZE) begin
                            shake_data_in <= xi[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                            in_last <= 0;
                        end else begin
                            shake_data_in <= { (DATA_IN_BITS-16)'(0), 8'(K), 8'(L) };
                            feed_cnt <= 0;
                            in_last <= 1;
                        end 
                    end
                end
                SQUEEZE_RHO: begin
                    ram_we_a <= 0;
                    if(shake_out_valid) begin
                        ram_we_a <= 1;
                        ram_din_a <= shake_data_out;
                        ram_addr_a <= RHO_BASE_OFFSET + squeeze_cnt;
                        squeeze_cnt <= (squeeze_cnt < SQUEEZE_RHO_BLOCK-1) ?
                                        (squeeze_cnt + 1) : 0;
                    end
                end
                SQUEEZE_RHO_PRIME: begin
                    ram_we_a <= 0;
                    if(shake_out_ready) begin
                        ram_we_a <= 1;
                        ram_din_a <= shake_data_out
                        ram_addr_a <= RHO_PRIME_BASE_OFFSET + squeeze_cnt;
                        squeeze_cnt <= (squeeze_cnt < SQUEEZE_RHO_PRIME_BLOCK-1) ?
                                        (squeeze_cnt + 1) : 0;
                    end
                end
                SQUEEZE_K: begin
                    ram_we_a <= 0;
                    if(shake_out_ready) begin
                        ram_we_a <= 1;
                        ram_din_a <= shake_data_out
                        ram_addr_a <= K_BASE_OFFSET + squeeze_cnt;
                        squeeze_cnt <= (squeeze_cnt < SQUEEZE_K_BLOCK-1) ?
                                        (squeeze_cnt + 1) : 0;
                        if(squeeze_cnt >= SQUEEZE_K_BLOCK-1) begin
                            expandA_start <= 1;
                            ram_addr_a_data <= RHO_BASE_OFFSET;
                            cache_rst <= 1;
                        end
                    end
                end
                EXPAND_A: begin
                    expandA_start <= 0;
                    cache_rst <= 0;
                    if(expandA_rho_block < EXPAND_A_RHO_BLOCK) begin
                        // in_valid <= 1;
                        expandA_rho_block <= expandA_rho_block + 1;
                        expandA_rho <= ram_dout_a_data;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end 
                    if (expandA_done) begin
                        expandS_start <= 1;
                        ram_addr_a_data <= RHO_PRIME_BASE_OFFSET;
                        cache_rst <= 1;
                    end
                end
                EXPAND_S: begin
                    expandS_start <= 0;
                    cache_rst <= 0;
                    if(expandS_rho_block < EXPAND_S_RHO_BLOCK) begin
                        // in_valid <= 1;
                        expandS_rho_block <= expandS_rho_block + 1;
                        expandS_rho <= ram_dout_a_data;
                        ram_addr_a_data <= ram_addr_a_data + 1;
                    end
                    if (expandS_done) begin
                        //TODO: setup for next state CALCULATE_T_0 
                    end
                end
                CALCULATE_T_0: begin
                end
                CALCULATE_T_1: begin
                end
                CALCULATE_T_2: begin
                end
                CALCULATE_T_3: begin
                end
                PK_ENCODE_RHO: begin

                end
                PK_ENCODE_T1: begin

                end
                SK_ENCODE_RHO: begin

                end
                SK_ENCODE_K: begin

                end
                SK_ENCODE_TR: begin

                end
                SK_ENCODE_S: begin

                end
                SK_ENCODE_T0: begin
                    
                end
            endcase
        end
    end

endmodule