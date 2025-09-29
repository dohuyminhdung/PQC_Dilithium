`timescale 1ns / 1ps
// Algorithm 34: Sampling the vector y, FIPS 204 page 38, slide 48
// Samples vector y in R_q^l with coefficients in [-gamma1 + 1, gamma1]
// Input: rho is a 64-byte seed, mu is a non-negative integer
// Output: Vector y of polynomials in R_q
//         Each entry is a polynomial (list of 256 coefficients mod q)

module ExpandMask #(
    parameter int SEED_SIZE = 64 * 8, //SHALL NOT MODIFY
    parameter int RHO_PRIME = 66 * 8, //SHALL NOT MODIFY 
    parameter int L = 7,
    parameter int N = 256,
    parameter int GAMMA1 = 19, // actually gamma1 = 2^this_parameter
    //parameter int MAX_LOOPS = 814, //Appendix C - Loop Bounds for ML-DSA.Sign_internal
                                    //FIPS204, page 52, slide 62
    parameter int COEFF_WIDTH = GAMMA1 + 1, //step 1 of Algorithm 34: c = 1 + bitlen(gamma1-1)

    //parameter for shake256 instance
    parameter int DATA_IN_BITS = 64,
    parameter int DATA_OUT_BITS = 64,
    //parameter for BRAM cache instance
    parameter int ADDR_WIDTH = $clog2(1088 / DATA_OUT_BITS),
    parameter int DATA_WIDTH = DATA_OUT_BITS
) (
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,
    input  wire [SEED_SIZE-1 : 0]          rho,
    input  wire [15 : 0]                    mu,
    output wire                             done,
    
    //output reg  [N * COEFF_WIDTH - 1 : 0]   y[L],
    //vector y is stored in BRAM, each coeff is COEFF_WIDTH bit wide
    //total bits = L * N * COEFF_WIDTH = 7 * 256 * 20 = 35840 bits = 4480 bytes
    //each word is a coeff => need N * L = 256 * 7 = 1792 words (log2(1792) = 11)
    output reg we_vector_y,
    output reg [$clog2(N*L)-1:0]    addr_vector_y, // N * L = 256 * 7 = 1792 words (log2(1792) = 11)
    output reg [23:0]               din_vector_y,

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
    localparam int IN_LAST_LEN = (RHO_PRIME % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (RHO_PRIME % DATA_IN_BITS);
    assign last_len = IN_LAST_LEN;

    localparam integer gamma1 = (1 << GAMMA1);

    // Absorb state
    reg  [$clog2(SEED_SIZE) : 0]       feed_cnt;
    // Squeeze state
    localparam int SQUEEZE_BLOCK = 1088 / DATA_OUT_BITS;
    reg  [ADDR_WIDTH-1:0]               squeeze_cnt; //[0, 17], tracking current block
    reg  [ADDR_WIDTH-1:0]               addr_squeeze; //input writing to RAM
    // Unpack state
    reg  [ADDR_WIDTH-1:0]               addr_unpack; //[0, 17], number blocks used
    localparam int UNPACK_BUFFER_SIZE = DATA_OUT_BITS + COEFF_WIDTH - (DATA_OUT_BITS % COEFF_WIDTH);
    reg  [UNPACK_BUFFER_SIZE-1:0]                       unpack_buffer;
    reg  [$clog2(UNPACK_BUFFER_SIZE)-1 : 0]             unpack_buffer_left;
    reg  [3:0]                                          poly_cnt; //0 => L=7
    reg  [$clog2(N) : 0]                                coeff_cnt;//0 => 256
    wire [15:0] mu_plus_r;      //IntegerToBytes(mu+r, 2)
    assign mu_plus_r = mu + poly_cnt; //step 3 of Algorithm 34: rho' = rho||IntegerToBytes(mu+r, 2)
    assign done = poly_cnt >= L;
                 
    // ------------------------------------------------------------
    // Signals for BRAM cache
    reg                     we_squeeze, we_unpack; //shall assign wr_en_unpack = 0 forever
    reg  [DATA_WIDTH-1:0]   din_squeeze, din_unpack; //data_in_unpack is useless
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
        .we_b(we_unpack),
        .addr_b(addr_unpack),
        .din_b(din_unpack),
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
        // ------------------------------------------------------------
        // Next-state logic
        // ------------------------------------------------------------
        next_state = state;
        case (state)
            IDLE: begin
                if(start) 
                    next_state = ABSORB;
            end

            ABSORB: begin
                if (in_ready && in_last) 
                    next_state = SQUEEZE;
            end

            SQUEEZE: begin
                if (squeeze_cnt >= SQUEEZE_BLOCK)
                    next_state = UNPACK;
            end

            UNPACK: begin
                if (done)
                    next_state = IDLE;
                else if (coeff_cnt >= 256)
                    next_state = ABSORB;
                else if (addr_unpack >= SQUEEZE_BLOCK) 
                    next_state = SQUEEZE;
                
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            //vector y signals
            we_vector_y <= 0;
            addr_vector_y <= -1;
            din_vector_y <= 0;

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

            //cache signals
            we_squeeze <= 0;
            we_unpack <= 0;
            din_squeeze <= 0;
            din_unpack <= 0;
        end else begin
            case (state)
                IDLE: begin
                    //vector y signals
                    we_vector_y <= 0;
                    addr_vector_y <= -1;
                    din_vector_y <= 0;

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

                    //cache signals
                    we_squeeze <= 0;
                    we_unpack <= 0;
                    din_squeeze <= 0;
                    din_unpack <= 0;
                end

                ABSORB: begin
                    //Total feed bits = 66 * 8 = 528 < 1088
                    //feed_cnt <= feed_cnt + DATA_IN_BITS;
                    in_valid <= 1;
                    //in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    // addr_squeeze <= 0;
                    we_squeeze <= 0;
                    absorb_next_poly <= 0;
                    addr_unpack <= 0;
                    we_vector_y <= 0;

                    if (in_ready) begin
                        if(feed_cnt >= SEED_SIZE) begin
                            in_last <= 1;
                            shake_data_in <= mu_plus_r;
                        end else begin
                            in_last <= 0;
                            shake_data_in <= rho[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                        end
                    end
                end

                SQUEEZE: begin //using port A
                    feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 1;
                    //squeeze_cnt <= squeeze_cnt + 1;
                    //addr_squeeze <= squeeze_cnt;
                    we_squeeze <= 0;
                    absorb_next_poly <= 0;
                    addr_unpack <= 0;
                    we_vector_y <= 0;

                    if(out_valid) begin
                        we_squeeze <= 1;
                        addr_squeeze <= squeeze_cnt;
                        din_squeeze <= shake_data_out;
                        squeeze_cnt <= squeeze_cnt + 1;
                    end
                end

                UNPACK: begin //using port B
                    feed_cnt <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;
                    squeeze_cnt <= 0;
                    addr_squeeze <= 0;
                    we_squeeze <= 0;
                    absorb_next_poly <= 0;
                    //addr_unpack <= addr_unpack + 1;
                    //we_vector_y <= 1;
                    
                    if(coeff_cnt < 256) begin 
                        if(unpack_buffer_left < COEFF_WIDTH) begin //read next word
                            unpack_buffer <= unpack_buffer | (dout_unpack << unpack_buffer_left);
                            unpack_buffer_left <= unpack_buffer_left + DATA_OUT_BITS;
                            addr_unpack <= addr_unpack + 1;
                        end else begin //consuming current word
                            we_vector_y <= 1;
                            din_vector_y <= gamma1 - unpack_buffer[0 +: COEFF_WIDTH];
                        
                            unpack_buffer_left <= unpack_buffer_left - COEFF_WIDTH;
                            unpack_buffer <= unpack_buffer >> COEFF_WIDTH;

                            coeff_cnt <= coeff_cnt + 1;
                            addr_vector_y <= addr_vector_y + 1;
                        end
                    end else begin
                        we_vector_y <= 0;
                        coeff_cnt <= 0;
                        addr_vector_y <= addr_vector_y;
                        poly_cnt <= poly_cnt + 1;
                        absorb_next_poly <= 1;
                        //reset addr_unpack for next poly
                        addr_unpack <= 0;
                    end
                end
            endcase
        end
    end

    //c = 1 + bitlen(gamma1-1) = COEFF_WIDTH
    //for r = poly_cnt form 0 to (l-1)
        //rho' = rho||bytes(mu+r, 2) = rho||mu_plus_r
        //v = SHAKE256(rho', 32 * c) = feed (rho) + (mu_plus_r with in_last = 1)
        //y[r] = BitUnPack(v, gamma-1, gamma1):
            //c = 20 = COEFF_WIDTH
            //for i from 0 to 255 (total 256 * 20 = 5120 bit)
            //y[r][i] = gamma1 - v[i*c +: c] 

endmodule