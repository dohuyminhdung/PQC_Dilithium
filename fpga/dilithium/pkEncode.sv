`timescale 1ns / 1ps
// Algorithm 22: Public key encoding (see FIPS 204, page 33, slide 43)
// Purpose: Encode a public key for ML-DSA into a byte string
//
// Input: 
//   - rho: 32 bytes
//   - t1 : list of k polynomials in R_q^k, 
//          with coefficients in [0, 2^(23-1-d)-1])
//
// Output: 
//   - pk : byte string of length = 32 + 32*k*(bitlen(q-1)-d) = 32 + 32 * 8 * (bitlen(8380417)-13) = 32 + 32 * 8 * 10 = 2592 bytes 
//
// Important notes:
//   - pkEncode is only used internally in KeyGen (Algorithm 6).
//   - The function is short and only processes data produced by KeyGen, so it is better implemented directly as a STATE inside the KeyGen module.
//   - This standalone pkEncode module is created **only for functional testing** before integration into KeyGen.

module pkEncode #(
    parameter int K = 8,
    parameter int D = 13,       //number of bits used for rounding during compression of polynomial coefficients.
    parameter int N = 256,
    parameter int RHO_SIZE = 32 * 8,
    parameter int COEFF_PACK_LENGTH = $clog2(8380417-1) - D; //(bitlen(q-1)-d)
    parameter int WORD_WIDTH = 64, //data width of a word RAM for packing data
    parameter int COEFF_WIDTH = 24,     //length of a coefficients in Z_q
    parameter int COEFF_PER_WORD = 4,
    parameter int POLY_WORD_WIDTH = 24 * COEFF_PER_WORD, //a block RAM of a polynomial, including 4 coeff
    parameter int ADDR_PACK_WIDTH = $clog2((32 + 32 * 8 * 10)*8),   //temporary variable 
    parameter int PK_BASE_OFFSET = 0                                //temporary variable
)(
    input  wire                         clk,
    input  wire                         rst,
    input  wire                         start,      //pulse 1 cycle     

    input  wire [WORD_WIDTH-1:0]        rho_in,     //each block of rho, total of (RHO_SIZE / WORD_WIDTH) = 32*8 / 64 = 4 blocks
    input  wire                         t_in_ok,
    input  wire [POLY_WORD_WIDTH-1:0]   t_coeff,    //each 4 coeff of an polynomial
    
    output reg                          done,
    output reg                          we_pk,
    output reg  [ADDR_PACK_WIDTH-1:0]   addr_pk,
    output reg  [WORD_WIDTH-1:0]        din_pk
);
    reg [$clog2(RHO_SIZE/WORD_WIDTH):0] rho_feed_cnt;
    localparam TOTAL_COEFF = K * N;
    reg [$clog2(TOTAL_COEFF):0]         coeff_t_cnt;

    localparam BUFFER_SIZE = WORD_WIDTH + COEFF_PACK_LENGTH * COEFF_PER_WORD;
    reg [BUFFER_SIZE-1:0]           vector_t_buffer;
    reg [$clog2(BUFFER_SIZE)-1:0]   vector_t_buffer_cnt;

    //TODO
    wire [COEFF_PACK_LENGTH-1:0] coeff3;
    wire [COEFF_PACK_LENGTH-1:0] coeff2;
    wire [COEFF_PACK_LENGTH-1:0] coeff1;
    wire [COEFF_PACK_LENGTH-1:0] coeff0;

    // FSM state encoding
    localparam IDLE             = 2'd0;
    localparam RHO_FEED         = 2'd1;
    localparam VECTOR_t_FEED    = 2'd2;
    reg  [1:0] state, next_state;   

    // Sequential state register
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
                    next_state = RHO_FEED;                
            end

            RHO_FEED: begin
                if(rho_feed_cnt >= RHO_SIZE/WORD_WIDTH-1)
                    next_state = VECTOR_t_FEED;
            end

            VECTOR_t_FEED: begin
                if(coeff_t_cnt >= TOTAL_COEFF-1)
                    next_state = IDLE;            
            end
        endcase
    end

    always @(posedge clk) begin
        if(rst) begin
            done <= 0;
            we_pk <= 0;
        end else begin
            case(state)
                IDLE: begin
                    done <= 0;
                    we_pk <= 0;
                    rho_feed_cnt <= 0;
                    coeff_t_cnt <= 0;
                end

                RHO_FEED: begin
                    we_pk = 1;
                    addr_pk <= PK_BASE_OFFSET + rho_feed_cnt;
                    din_pk <= rho_in;
                    rho_feed_cnt <= rho_feed_cnt + 1; 
                end

                VECTOR_t_FEED: begin
                    if(vector_t_buffer_cnt < WORD_WIDTH) begin
                        we_pk <= 0;
                        t_in_ok <= 1;
                        //TODO

                    end else begin
                        we_pk <= 1;
                        addr_pk <= PK_BASE_OFFSET + (RHO_SIZE / WORD_WIDTH) + (coeff_t_cnt/COEFF_PER_WORD);
                        din_pk <= vector_t_buffer[0+:WORD_WIDTH];

                        vector_t_buffer <= vector_t_buffer >> WORD_WIDTH;
                        vector_t_buffer_cnt <= vector_t_buffer_cnt - WORD_WIDTH;
                    end
                end
            endcase
        end
    end
endmodule