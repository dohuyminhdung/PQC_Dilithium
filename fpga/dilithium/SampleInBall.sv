`timescale 1ns / 1ps

// Algorithm 29: Sampling the challenge polynomial c, FIPS 204 page 36, slide 46
// Samples a polynomial c in R_q with coefficients in {-1, 0, 1} and Hamming weight tau <= 64
// Input: rho (typically lambda/4 = 256/4 = 64 bytes from H(mu || w1Encode(w1)) in Sign)
// Output: A polynomial c in R_q (list of 256 coefficients in R_q)

module SampleInBall #( 
    parameter int N = 256,                  // output are 256 coefficients from a polynomial
    parameter int LAMBDA = 256,             // collision strength of c~
    parameter int TAU = 60,                 // Hamming weight of c
    parameter int SEED_SIZE = LAMBDA/4*8,   // 64 bytes = 512 bits
    parameter int COEFF_WIDTH = 24,
    parameter int WORD_LEN = COEFF_WIDTH * 4,
    //parameter for shake256 instance
    parameter int DATA_IN_BITS = 64,
    parameter int DATA_OUT_BITS = 64,
    //parameter for BRAM cache instance
    parameter int ADDR_WIDTH = $clog2(1088 / DATA_OUT_BITS),
    parameter int DATA_WIDTH = DATA_OUT_BITS,
    parameter int ADDR_POLY_WIDTH = $clog2(N*COEFF_WIDTH/WORD_LEN+1)
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle
    input  wire [SEED_SIZE-1 : 0]           rho,        //64 bytes
    output wire                             done,       //pulse 1 cycle
    
    //total N * COEFF_WIDTH = 6144 bit = 768 byte
    output reg we_poly_c,
    output reg [ADDR_POLY_WIDTH-1:0]        addr_poly_c,  
    output reg [WORD_LEN-1:0]               din_poly_c,

    //shake256 instance
    output reg  [DATA_IN_BITS-1:0]          shake_data_in,
    output reg                              in_valid,
    output reg                              in_last,
    output wire [$clog2(DATA_IN_BITS) : 0]  last_len,
    output reg                              out_ready,
    input  wire [DATA_OUT_BITS-1:0]         shake_data_out,
    input  wire                             out_valid,
    input  wire                             in_ready
);
    reg  [2*N-1:0] poly_raw; //2 bit for each coeff in range (-1, 0, 1)

    localparam int IN_LAST_LEN = (SEED_SIZE % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (SEED_SIZE % DATA_IN_BITS);
    assign last_len = IN_LAST_LEN;
    // absorb state
    reg [$clog2(SEED_SIZE) : 0] feed_cnt;
    // squeeze state
    localparam int SQUEEZE_BLOCK = 1088 / DATA_OUT_BITS;
    reg  [ADDR_WIDTH-1:0]           squeeze_cnt; //[0, 17], tracking current block
    reg  [ADDR_WIDTH-1:0]           addr_squeeze; //input writing to RAM
    // sample state
    reg  [ADDR_WIDTH-1:0]           addr_unpack; //[0, 17], number blocks used
    localparam int UNPACK_BUFFER_SIZE = DATA_OUT_BITS + 8;
    reg  [UNPACK_BUFFER_SIZE:0]             unpack_buffer;
    reg  [$clog2(UNPACK_BUFFER_SIZE)-1:0]   unpack_buffer_left;
    reg  [$clog2(N) : 0] coeff_cnt; //i in step 6, 196 => 255
    reg [63:0]  pre_sample_buffer;  // buffer for pre-sampling (step 4 in Algorithm 29)
    reg         pre_sample_done;    // pre-sample state will squeeze 1 for step 4 and 1 more for next sampling state
    // unpack state
    localparam int IS_POSITIVE_ONE = 1;
    localparam int IS_NEGATIVE_ONE = 2;
    reg [$clog2(N) : 0]         coeff_unpack_cnt;
    reg [WORD_LEN-1:0]          coeff_per_word;
    reg [$clog2(WORD_LEN):0]    coeff_per_word_cnt;
    assign done = coeff_unpack_cnt >= N + (WORD_LEN/COEFF_WIDTH);

    function [COEFF_WIDTH-1:0] HammingModQ;
        input [1:0] b;
        begin
            case (b)
                2'd0: HammingModQ = COEFF_WIDTH'(0);
                2'd1: HammingModQ = COEFF_WIDTH'(1);  
                default: HammingModQ = COEFF_WIDTH'(8380416);
            endcase
        end
    endfunction
    wire [COEFF_WIDTH-1:0] coeff0, coeff1, coeff2, coeff3;
    assign coeff0 = COEFF_WIDTH'(HammingModQ(poly_raw[0+:2]));
    assign coeff1 = COEFF_WIDTH'(HammingModQ(poly_raw[2+:2]));
    assign coeff2 = COEFF_WIDTH'(HammingModQ(poly_raw[4+:2]));
    assign coeff3 = COEFF_WIDTH'(HammingModQ(poly_raw[6+:2]));

    // ------------------------------------------------------------
    // Signals for SHAKE256 buffer
    reg                     we_squeeze; 
    reg  [DATA_WIDTH-1:0]   din_squeeze; 
    wire [DATA_WIDTH-1:0]   dout_unpack, dout_squeeze;//data_out_squeeze is useless
    dp_ram_true #(
        .ADDR_WIDTH(ADDR_WIDTH), 
        .DATA_WIDTH(DATA_WIDTH)
    ) shake_cache (   
        .clk(clk),
        .we_a(we_squeeze),
        .addr_a(addr_squeeze),
        .din_a(din_squeeze),
        .dout_a(dout_squeeze),
        .we_b(0),   //shall assign wr_en_unpack = 0 forever
        .addr_b(addr_unpack),
        .din_b(0), //data_in_unpack is useless
        .dout_b(dout_unpack)
    );
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // FSM state encoding
    localparam IDLE         = 3'd0;
    localparam ABSORB       = 3'd1;
    localparam SQUEEZE      = 3'd2;
    localparam PRE_SAMPLE   = 3'd3;
    localparam SAMPLING     = 3'd4;
    localparam UNPACK       = 3'd5;
    reg  [2:0] state, next_state;
    // ------------------------------------------------------------

    always @(posedge clk) begin
        if (rst) begin
            state <= IDLE;
        end else begin
            state <= next_state;
        end
    end

    always @* begin
        next_state = state;
        case (state)
            IDLE: begin
                if (start)
                    next_state = ABSORB;
            end
            ABSORB: begin
                if (in_ready && (feed_cnt + DATA_IN_BITS >= SEED_SIZE))
                    next_state = SQUEEZE;
            end
            SQUEEZE: begin
                if (squeeze_cnt >= SQUEEZE_BLOCK) 
                    next_state = pre_sample_done ? SAMPLING : PRE_SAMPLE;
            end
            PRE_SAMPLE: begin
                if (pre_sample_done) begin
                    next_state = SAMPLING;
                end
            end
            SAMPLING: begin
                if(coeff_cnt >= N-1)
                    next_state = UNPACK;
                else if (addr_unpack >= SQUEEZE_BLOCK)
                    next_state = SQUEEZE;
            end
            UNPACK: begin
                if(done)
                    next_state = IDLE;
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            //vector s signals
            we_poly_c <= 0;
            addr_poly_c <= -1;
            din_poly_c <= 0;

            //shake signals
            shake_data_in <= 0;
            in_valid <= 0;
            in_last <= 0;
            out_ready <= 0;

            poly_raw <= 0;
            
            //absorb signals
            feed_cnt <= 0;
            
            //squeeze signals
            squeeze_cnt <= 0;
            addr_squeeze <= 0;
            
            //sample signals
            addr_unpack <= 0;
            unpack_buffer <= 0;
            unpack_buffer_left <= 0;
            coeff_cnt <= 256 - TAU;
            pre_sample_done <= 0;
            pre_sample_buffer <= 0;
            
            //unpack signals
            coeff_unpack_cnt <= 0;
            coeff_per_word <= 0;
            coeff_per_word_cnt <= 0;
            
            //cache signals
            we_squeeze <= 0;
            din_squeeze <= 0;
        end else begin
            case (state)
                IDLE: begin
                    //vector s signals
                    we_poly_c <= 0;
                    addr_poly_c <= -1;
                    din_poly_c <= 0;

                    //shake signals
                    shake_data_in <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;

                    poly_raw <= 0;
                    
                    //absorb signals
                    feed_cnt <= 0;
                    
                    //squeeze signals
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    
                    //sample signals
                    addr_unpack <= 0;
                    unpack_buffer <= 0;
                    unpack_buffer_left <= 0;
                    coeff_cnt <= 256 - TAU;
                    pre_sample_done <= 0;
                    pre_sample_buffer <= 0;
                    
                    //unpack signals
                    coeff_unpack_cnt <= 0;
                    coeff_per_word <= 0;
                    coeff_per_word_cnt <= 0;
                    
                    //cache signals
                    we_squeeze <= 0;
                    din_squeeze <= 0;
                end
                ABSORB: begin
                    //64 * 8 = 512 < RATE = 1088 => absorb_block will never overflow
                    //feed_cnt <= feed_cnt + DATA_IN_BITS;
                    //in_valid <= 1;
                    //in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    // addr_squeeze <= 0;
                    we_squeeze <= 0;
                    addr_unpack <= 0;
                    we_poly_c <= 0;

                    if(in_ready) begin
                        in_valid <= 1;
                        shake_data_in <= rho[feed_cnt +: DATA_IN_BITS];
                        feed_cnt <= feed_cnt + DATA_IN_BITS;
                        if(feed_cnt + DATA_IN_BITS >= SEED_SIZE) 
                            in_last <= 1; //send final block with in_last = 1
                        else 
                            in_last <= 0;
                    end
                end
                SQUEEZE: begin
                    feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 1;
                    //squeeze_cnt <= squeeze_cnt + 1;
                    //addr_squeeze <= squeeze_cnt;
                    we_squeeze <= 0;
                    addr_unpack <= 0;
                    we_poly_c <= 0;

                    if(out_valid) begin
                        we_squeeze <= 1;
                        addr_squeeze <= squeeze_cnt;
                        din_squeeze <= shake_data_out;
                        squeeze_cnt <= squeeze_cnt + 1;
                    end
                end
                PRE_SAMPLE: begin
                    if(!pre_sample_done) begin
                        unpack_buffer <= dout_unpack;
                        unpack_buffer_left <= DATA_OUT_BITS;
                        addr_unpack <= addr_unpack + 1;
                        pre_sample_done <= 1;
                    end else begin //pre_sample_done == 1
                        pre_sample_buffer <= unpack_buffer[0+:64]; //step 4: (ctx, s) <= H.Squeeze(ctx, 8 byte)
                        unpack_buffer <= unpack_buffer >> 64;
                        unpack_buffer_left <= unpack_buffer_left - 64;
                    end
                end
                SAMPLING: begin
                    feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    we_squeeze <= 0;
                    //addr_unpack <= addr_unpack;
                    we_poly_c <= 0;

                    if(unpack_buffer_left < 8) begin //read next word
                        unpack_buffer <= unpack_buffer | (dout_unpack << unpack_buffer_left);
                        unpack_buffer_left <= unpack_buffer_left + DATA_OUT_BITS;
                        addr_unpack <= addr_unpack + 1;
                    end else begin
                        if(unpack_buffer[0+:8] <= coeff_cnt) begin
                            coeff_cnt <= coeff_cnt + 1;
                            poly_raw[coeff_cnt          *2  +:2] <= 2'(poly_raw[unpack_buffer[0+:8]*2  +:2]);
                            poly_raw[unpack_buffer[0+:8]*2  +:2] <= pre_sample_buffer[coeff_cnt+TAU-256] == 1'b1 ? 
                                                                2'(IS_NEGATIVE_ONE) : 
                                                                2'(IS_POSITIVE_ONE); 
                        end
                        unpack_buffer <= unpack_buffer >> 8;
                        unpack_buffer_left <= unpack_buffer_left - 8;
                    end
                end
                UNPACK: begin
                    we_poly_c <= 1;
                    addr_poly_c <= addr_poly_c + 1;
                    din_poly_c <= { {COEFF_WIDTH'(coeff3)}, {COEFF_WIDTH'(coeff2)}, {COEFF_WIDTH'(coeff1)}, {COEFF_WIDTH'(coeff0)} };
                    coeff_unpack_cnt <= coeff_unpack_cnt + 4;
                    poly_raw <= poly_raw >> 8; //4 coeff * 2 bit per coeff
                end
            endcase
        end
    end
endmodule