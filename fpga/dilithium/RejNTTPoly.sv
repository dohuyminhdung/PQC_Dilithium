`timescale 1ns / 1ps
// Algorithm 30: Rejection sampling, FIPS 204 page 37, slide 47
// Samples a polynomial in T_q
// Input: seed (typically 34 bytes from rho || s || r in ExpandA)
// Output: An element in T_q (list of 256 coefficients in T_q)

module RejNTTPoly #(  
    parameter int SEED_SIZE = 34*8,  // SHALL NOT MODIFY
    parameter int K = 8,             // number of rows
    parameter int L = 7,             // number of columns
    parameter int N = 256,           // output are 256 coefficients from a polynomial
    parameter int COEFF_WIDTH = 24,  // coefficient width is log2(q) = 23-bit ~ 24-bits for align word
    parameter int WORD_LEN = COEFF_WIDTH * 4,
    parameter int DATA_IN_BITS = 64, //should divisible by 8
    parameter int DATA_OUT_BITS = 64,//should divisible by 8
    //parameter for BRAM cache instance
    parameter int ADDR_WIDTH = $clog2(1344 / DATA_OUT_BITS),
    parameter int DATA_WIDTH = DATA_OUT_BITS,
    parameter int ADDR_POLY_WIDTH = $clog2(K*L*N*COEFF_WIDTH/WORD_LEN)
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [SEED_SIZE-1 : 0]           rho,        //34 bytes         
    output reg                              done,       //sampling done, pulse 1 cycle     
    
    //output reg  [COEFF_WIDTH * N - 1 : 0]   poly   //packed polynomial output
    //matrix A is stored in BRAM, each coeff is 24 bit width
    //total bits = K * L * 256 * 24 = 344064 bits = 43008 bytes
    input  wire [3:0]   k, l,
    output reg          we_matA,                //need K * L * N = 14336 word
    output reg [ADDR_POLY_WIDTH-1:0]    addr_matA,  //offset(k,l,n) = k*(L*N) + l*N + n
    output reg [WORD_LEN-1:0]           din_matA,

    // shake128 instance
    // output reg                              absorb_next_poly,
    output reg  [DATA_IN_BITS-1:0]          shake_data_in,
    output reg                              in_valid,
    output reg                              in_last,
    output wire [$clog2(DATA_IN_BITS):0]    last_len,
    output reg                              out_ready,
    input wire [DATA_OUT_BITS-1:0]          shake_data_out,
    input wire                              out_valid,
    input wire                              in_ready
);
    localparam int Q = 8380417; //2^23 - 2^13 + 1
    localparam int IN_LAST_LEN = (SEED_SIZE % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (SEED_SIZE % DATA_IN_BITS);
    assign last_len = IN_LAST_LEN;

    // absorb state
    reg [$clog2(SEED_SIZE) : 0] feed_cnt;
    // squeeze state
    localparam int SQUEEZE_BLOCK = 1344 / DATA_OUT_BITS; 
    reg  [ADDR_WIDTH-1:0]               squeeze_cnt; //[0, 21], tracking current block
    reg  [ADDR_WIDTH-1:0]               addr_squeeze; //input writing to RAM
    // unpack state
    reg  [ADDR_WIDTH-1:0]               addr_unpack; //[0, 21], number blocks used
    localparam int UNPACK_BUFFER_SIZE = DATA_OUT_BITS + COEFF_WIDTH;
    reg  [UNPACK_BUFFER_SIZE-1:0]                       unpack_buffer;
    reg  [$clog2(UNPACK_BUFFER_SIZE)-1 : 0]             unpack_buffer_left;
    reg  [$clog2(N) : 0]                                coeff_cnt;//0 => 256
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
        .we_b(0), //shall assign wr_en_unpack = 0 forever
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
        done = 0;
        case (state)
            IDLE: begin
                if (start) begin
                    next_state = ABSORB;
                end
            end
            ABSORB: begin
                if (in_ready && (feed_cnt + DATA_IN_BITS >= SEED_SIZE))
                    next_state = SQUEEZE;
            end
            SQUEEZE: begin
                if (squeeze_cnt >= SQUEEZE_BLOCK) 
                    next_state = UNPACK;
            end
            UNPACK: begin
                if(coeff_cnt >= N) begin
                    next_state = IDLE;
                    done = 1;
                end else if(addr_unpack >= SQUEEZE_BLOCK)
                    next_state = SQUEEZE;
            end
        endcase
    end

    // ------------------------------------------------------------
    // Output / handshake signals
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            // matA signals
            we_matA <= 0;
            addr_matA <= 0;
            din_matA <= 0;

            //shake signals
            shake_data_in <= 0;
            in_valid <= 0;
            in_last <= 0;
            out_ready <= 0;

            // absorb signals
            feed_cnt    <= 0;
            // squeeze signals
            squeeze_cnt <= 0;
            addr_squeeze <= 0;
            // unpack signals
            addr_unpack <= 0;
            unpack_buffer <= 0;
            unpack_buffer_left <= 0;
            coeff_cnt <= 0;
            coeff_per_word <= 0;
            coeff_per_word_cnt <= 0;

            //cache signals
            we_squeeze <= 0;
            din_squeeze <= 0;
        end else begin
            case (state)
                IDLE: begin
                    // matA signals
                    we_matA <= 0;
                    addr_matA <= 0;
                    din_matA <= 0;

                    //shake signals
                    shake_data_in <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;

                    // absorb signals
                    feed_cnt    <= 0;
                    // squeeze signals
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    // unpack signals
                    addr_unpack <= 0;
                    unpack_buffer <= 0;
                    unpack_buffer_left <= 0;
                    coeff_cnt <= 0;
                    coeff_per_word <= 0;
                    coeff_per_word_cnt <= 0;

                    //cache signals
                    we_squeeze <= 0;
                    din_squeeze <= 0;
                end
                ABSORB: begin
                    //34 * 8 = 272 < RATE = 1344 => absorb_block will never overflow
                    //feed_cnt <= feed_cnt + DATA_IN_BITS;
                    // in_valid <= 1;
                    //in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    //addr_squeeze <= 0;
                    we_squeeze <= 0;
                    addr_unpack <= 0;
                    we_matA <= 0;

                    if(in_ready) begin
                        in_valid <= 1;
                        if(feed_cnt + DATA_IN_BITS < SEED_SIZE) begin
                            shake_data_in <= rho[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                            in_last <= 0;
                        end else begin
                            shake_data_in <= { {(DATA_IN_BITS - IN_LAST_LEN){1'b0}}, rho[feed_cnt +: IN_LAST_LEN]};
                            feed_cnt <= 0;
                            in_last <= 1;
                        end
                    end
                end

                SQUEEZE: begin
                    // feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 1;
                    // squeeze_cnt <= squeeze_cnt + 1;
                    // addr_squeeze <= squeeze_cnt;
                    we_squeeze <= 0;
                    addr_unpack <= 0;
                    we_matA <= 0;

                    if(out_valid) begin
                        we_squeeze <= 1;
                        din_squeeze <= shake_data_out;
                        addr_squeeze <= squeeze_cnt;
                        squeeze_cnt <= squeeze_cnt + 1;
                    end
                end

                UNPACK: begin
                    // feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    we_squeeze <= 0;
                    // addr_unpack <= offset(k,l,n) = k*(L*N) + l*N + n;
                    we_matA <= 0;

                    if (coeff_cnt < N) begin
                        if(unpack_buffer_left < COEFF_WIDTH) begin
                            unpack_buffer <= unpack_buffer | (dout_unpack << unpack_buffer_left);
                            unpack_buffer_left <= unpack_buffer_left + DATA_OUT_BITS;
                            addr_unpack <= addr_unpack + 1;
                        end else if (coeff_per_word_cnt >= WORD_LEN) begin
                            we_matA <= 1;
                            din_matA <= coeff_per_word;
                            addr_matA <= ((k*(L*N) + l*N + coeff_cnt) >> 2);
                            coeff_cnt <= coeff_cnt + COEFF_PER_WORD;
                            coeff_per_word_cnt <= 0;
                        end else begin    
                            unpack_buffer_left <= unpack_buffer_left - 24;
                            unpack_buffer <= unpack_buffer >> 24;
                        // A14: Coeff gen from 3 bytes (p.29) applied here
                        // [22:0] b2b1b0 < Q ? accept : reject;
                            if(unpack_buffer[0+:23] < Q) begin //sample
                                coeff_per_word_cnt <= coeff_per_word_cnt + COEFF_WIDTH;
                                coeff_per_word[coeff_per_word_cnt+:COEFF_WIDTH] <= COEFF_WIDTH'(unpack_buffer[0+:23]);
                            end
                        end
                    end
                end
            endcase
        end
    end
endmodule