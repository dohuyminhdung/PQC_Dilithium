`timescale 1ns / 1ps
// Algorithm 33: Sampling the secret vectors s1 and s2, FIPS 204 page 38, slide 48
// Samples vector s1 in R_q^l and s2 in R_q^k with coefficients in [-eta, eta]
// Input: rho is a 64-byte seed
// Output: Vector s1 and s2 of polynomials in R_q
//         Each entry is a polynomial (list of 256 coefficients mod q)

module ExpandS #( 
    parameter int SEED_SIZE = 64*8,             //SHALL NOT MODIFY 
    parameter int REJ_BOUNDED_POLY_SEED = 66*8, //SHALL NOT MODIFY
    parameter int WORD_LEN = 96,                
    parameter int K = 8,                // number of rows
    parameter int L = 7,                // number of columns             
    parameter int N   = 256,            //output are 256 coefficients from a polynomial   
    parameter int ETA = 2,              //private key range in Dilithium
    parameter int COEFF_WIDTH = 24,      //coefficient is guarantee in range [-eta, eta] = [-2, 2]
    //parameter for shake256 instance
    parameter int DATA_IN_BITS = 64,
    parameter int DATA_OUT_BITS = 64,
    //parameter for BRAM cache instance
    parameter int ADDR_WIDTH = $clog2(1088 / DATA_OUT_BITS),
    parameter int DATA_WIDTH = DATA_OUT_BITS,
    parameter int ADDR_POLY_WIDTH = $clog2((L+K)*N*COEFF_WIDTH/WORD_LEN)
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [SEED_SIZE-1 : 0]           rho,        //64 bytes         
    output wire                             done,       //sampling done, pulse 1 cycle     
    
    //vector s1 and s2 is stored in BRAM, each coeff is 4 bit wide
    //total bits = (L+K)*N*4 = 15 * 256 * 4 = 15360 bits = 1920 bytes
    //each word is 2 coeff => need (L+K)*N/2 = 15 * 256 / 2 = 1920 words (log2(1920) = 11)
    
    output reg we_vector_s,
    output reg [ADDR_POLY_WIDTH-1:0]        addr_vector_s,  
    output reg [WORD_LEN-1:0]               din_vector_s,

    //shake256 instance
    output reg                              absorb_next_poly, //shake force reset
    output reg  [DATA_IN_BITS-1:0]          shake_data_in,
    output reg                              in_valid,
    output reg                              in_last,
    output wire [$clog2(DATA_IN_BITS) : 0]  last_len,
    output reg                              out_ready,
    input  wire [DATA_OUT_BITS-1:0]         shake_data_out,
    input  wire                             out_valid,
    input  wire                             in_ready
);
    localparam int IN_LAST_LEN = (REJ_BOUNDED_POLY_SEED % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (REJ_BOUNDED_POLY_SEED % DATA_IN_BITS);
    assign last_len = IN_LAST_LEN;

    // absorb state
    reg [$clog2(SEED_SIZE) : 0]     feed_cnt;
    // squeeze state
    localparam int SQUEEZE_BLOCK = 1088 / DATA_OUT_BITS;
    reg  [ADDR_WIDTH-1:0]           squeeze_cnt; //[0, 17], tracking current block
    reg  [ADDR_WIDTH-1:0]           addr_squeeze; //input writing to RAM
    // unpack state
    reg  [ADDR_WIDTH-1:0]           addr_unpack; //[0, 17], number blocks used
    localparam int UNPACK_BUFFER_SIZE = DATA_OUT_BITS + 4;
    reg  [UNPACK_BUFFER_SIZE:0]             unpack_buffer;
    reg  [$clog2(UNPACK_BUFFER_SIZE)-1:0]   unpack_buffer_left;
    reg  [$clog2(K+L):0]    poly_cnt; //0 => L + K = 15
    reg  [$clog2(N) : 0]    coeff_cnt;//0 => 256
    assign done = poly_cnt >= K + L;
    localparam int COEFF_PER_WORD = WORD_LEN / COEFF_WIDTH;
    reg [WORD_LEN-1:0]          coeff_per_word;
    reg [$clog2(WORD_LEN):0]    coeff_per_word_cnt;

    // ------------------------------------------------------------
    // Signals for BRAM cache
    reg                     we_squeeze; 
    reg  [DATA_WIDTH-1:0]   din_squeeze; 
    wire [DATA_WIDTH-1:0]   dout_squeeze, dout_unpack; //data_out_squeeze is useless
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
    localparam IDLE     = 2'd0;
    localparam ABSORB   = 2'd1;
    localparam SQUEEZE  = 2'd2;
    localparam UNPACK   = 2'd3;
    reg  [1:0] state, next_state;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Algorithm 15: Coefficient generation from a half byte, FIPS 204 page 30, slide 40
    // Generates an element of {-eta, ..., eta} from a half byte
    // Input:  A half byte b (0 <= b < 16)
    // Output: A 2's complement 4 bits number in {-eta, ..., eta}, currently only support eta = 2
    function [COEFF_WIDTH-1:0] CoeffFromHalfByte;
        input [3:0] b;
        begin
            case (b)
                4'd0:   CoeffFromHalfByte =  COEFF_WIDTH'(2);
                4'd1:   CoeffFromHalfByte =  COEFF_WIDTH'(1); 
                4'd2:   CoeffFromHalfByte =  COEFF_WIDTH'(0); 
                4'd3:   CoeffFromHalfByte =  COEFF_WIDTH'(8380416);  //-1 
                4'd4:   CoeffFromHalfByte =  COEFF_WIDTH'(8380415); //-2
                4'd5:   CoeffFromHalfByte =  COEFF_WIDTH'(2); 
                4'd6:   CoeffFromHalfByte =  COEFF_WIDTH'(1); 
                4'd7:   CoeffFromHalfByte =  COEFF_WIDTH'(0); 
                4'd8:   CoeffFromHalfByte =  COEFF_WIDTH'(8380416); //-1
                4'd9:   CoeffFromHalfByte =  COEFF_WIDTH'(8380415); //-2
                4'd10:  CoeffFromHalfByte =  COEFF_WIDTH'(2); 
                4'd11:  CoeffFromHalfByte =  COEFF_WIDTH'(1); 
                4'd12:  CoeffFromHalfByte =  COEFF_WIDTH'(0); 
                4'd13:  CoeffFromHalfByte =  COEFF_WIDTH'(8380416); //-1
                4'd14:  CoeffFromHalfByte =  COEFF_WIDTH'(8380415); //-2
                default: CoeffFromHalfByte =  0;
            endcase
        end
    endfunction
    // ------------------------------------------------------------ 

    // ------------------------------------------------------------
    // Sequential state register
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
                if (in_ready && (feed_cnt >= SEED_SIZE)) 
                    next_state = SQUEEZE;
            end
            SQUEEZE: begin
                if (squeeze_cnt >= SQUEEZE_BLOCK) 
                    next_state = UNPACK;
            end
            UNPACK: begin
                if(done)
                    next_state = IDLE;
                else if(coeff_cnt >= 256)
                    next_state = ABSORB;
                else if(addr_unpack >= SQUEEZE_BLOCK)
                    next_state = SQUEEZE;
            end
        endcase
    end

    // ------------------------------------------------------------
    // Output / handshake signals
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            //vector s signals
            we_vector_s <= 0;
            addr_vector_s <= -1;
            din_vector_s <= 0;

            //shake signals
            absorb_next_poly <= 0;
            shake_data_in <= 0;
            in_valid <= 0;
            in_last <= 0;
            out_ready <= 0;

            //absorb signals
            feed_cnt <= 0;
            //squeeze signals
            squeeze_cnt <= 0;
            addr_squeeze <= 0;
            //unpack signals
            addr_unpack <= 0;
            unpack_buffer <= 0;
            unpack_buffer_left <= 0;
            poly_cnt <= 0;
            coeff_cnt <= 0;
            coeff_per_word <= 0;
            coeff_per_word_cnt <= 0;

            //cache signals
            we_squeeze <= 0;
            din_squeeze <= 0;
        end else begin
            case (state)
                IDLE: begin
                   //vector s signals
                    we_vector_s <= 0;
                    addr_vector_s <= -1;
                    din_vector_s <= 0;

                    //shake signals
                    absorb_next_poly <= 0;
                    shake_data_in <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;

                    //absorb signals
                    feed_cnt <= 0;
                    //squeeze signals
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    //unpack signals
                    addr_unpack <= 0;
                    unpack_buffer <= 0;
                    unpack_buffer_left <= 0;
                    poly_cnt <= 0;
                    coeff_cnt <= 0;
                    coeff_per_word <= 0;
                    coeff_per_word_cnt <= 0;

                    //cache signals
                    we_squeeze <= 0;
                    din_squeeze <= 0;
                end
                ABSORB: begin
                    //66 * 8 = 528 < RATE = 1088 => absorb_block will never overflow
                    //feed_cnt <= feed_cnt + DATA_IN_BITS;
                    //in_valid <= 1;
                    //in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    // addr_squeeze <= 0;
                    we_squeeze <= 0;
                    absorb_next_poly <= 0;
                    addr_unpack <= 0;
                    we_vector_s <= 0;

                    if(in_ready) begin
                        in_valid <= 1;
                        if(feed_cnt >= SEED_SIZE) begin
                            in_last <= 1;
                            shake_data_in <= (poly_cnt);
                        end else begin
                            in_last <= 0;
                            shake_data_in <= rho[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                        end
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
                    absorb_next_poly <= 0;
                    addr_unpack <= 0;
                    we_vector_s <= 0;

                    if(out_valid) begin
                        we_squeeze <= 1;
                        addr_squeeze <= squeeze_cnt;
                        din_squeeze <= shake_data_out;
                        squeeze_cnt <= squeeze_cnt + 1;
                    end
                end
                UNPACK: begin
                    feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    we_squeeze <= 0;
                    absorb_next_poly <= 0;
                    //addr_unpack <= addr_unpack;
                    we_vector_s <= 0;

                    if(coeff_cnt < N) begin
                        if(unpack_buffer_left < 4) begin //read next word
                            unpack_buffer <= unpack_buffer | (dout_unpack << unpack_buffer_left);
                            unpack_buffer_left <= unpack_buffer_left + DATA_OUT_BITS;
                            addr_unpack <= addr_unpack + 1;
                        end else if (coeff_per_word_cnt >= WORD_LEN) begin
                            we_vector_s <= 1;
                            din_vector_s <= coeff_per_word;
                            addr_vector_s <= addr_vector_s + 1;
                            coeff_cnt <= coeff_cnt + COEFF_PER_WORD;
                            coeff_per_word_cnt <= 0;
                        end else begin
                            unpack_buffer_left <= unpack_buffer_left - 4;
                            unpack_buffer <= unpack_buffer >> 4;
                            if(unpack_buffer[0+:4] < 15) begin
                                coeff_per_word_cnt <= coeff_per_word_cnt + COEFF_WIDTH;
                                coeff_per_word[coeff_per_word_cnt+:COEFF_WIDTH] <= COEFF_WIDTH'(CoeffFromHalfByte(unpack_buffer[0+:4]));
                            end
                        end
                    end else begin
                        we_vector_s <= 0;
                        coeff_cnt <= 0;
                        addr_vector_s <= addr_vector_s;
                        poly_cnt <= poly_cnt + 1;
                        absorb_next_poly <= 1;
                        addr_unpack <= 0;
                        coeff_per_word <= 0;
                        coeff_per_word_cnt <= 0;
                        unpack_buffer <= 0;
                        unpack_buffer_left <= 0;
                    end
                end
            endcase
        end
    end
    //for l form 0 to L-1 do
    //  s[l] = RejBoundedPoly(rho||IntegerToBytes(l, 2)):
    //      ctx = SHAKE256.Absorb(seed)
    //      while i < 256:
    //          z = SHAKE256.Squeeze(1)
    //          s[l][i] = CoeffFromHalfByte(z)
    //for l from 0 to K-1 do
    //  s[L+l] = RejBoundedPoly(rho||IntegerToBytes(L+l, 2)):
    //      ctx = SHAKE256.Absorb(seed)
    //      while i < 256:
    //          z = SHAKE256.Squeeze(1)
    //          s[l][i] = CoeffFromHalfByte(z)
endmodule