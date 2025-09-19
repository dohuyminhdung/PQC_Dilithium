`timescale 1ns / 1ps

// Algorithm 30: Rejection sampling, FIPS 204 page 37, slide 47
// Samples a polynomial in T_q
// Input: seed (typically 34 bytes from rho || s || r in ExpandA)
// Output: An element in T_q (list of 256 coefficients in T_q)

//SHALL NOT MODIFY THESE MACRO
`define SEED_SIZE 34*8 
`define BYTE 8
`define Q 8380417 //2^23 - 2^13 + 1

module RejNTTPoly #( 
    parameter int N = 256,          // output are 256 coefficients from a polynomial
    parameter int COEFF_WIDTH = 24, // coefficient width is log2(q) = 23-bit value + 1-bit valid = 24 bits
    parameter int DATA_IN_BITS = 64, //should divisible by 8
    parameter int DATA_OUT_BITS = 64  //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [SEED_SIZE-1 : 0]           rho,        //34 bytes         
    output reg                              done,       //sampling done, pulse 1 cycle     
    output reg  [COEFF_WIDTH * N - 1 : 0]   poly   //packed polynomial output
);
    // ------------------------------------------------------------
    // FSM state encoding
    localparam IDLE     = 2'd0;
    localparam ABSORB   = 2'd1;
    localparam SQUEEZE  = 2'd2;
    reg  [1:0] state, next_state;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for shake128 instance
    reg  [DATA_IN_BITS-1:0]                  data_in;
    reg                                      in_valid;
    reg                                      in_last;
    localparam int LAST_LEN = (`SEED_SIZE % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (`SEED_SIZE % DATA_IN_BITS);
    reg                                      out_ready;
    wire [DATA_OUT_BITS-1:0]                 data_out;
    wire                                     out_valid;
    wire                                     in_ready;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for absorb state
    reg [$clog2(`SEED_SIZE) : 0] feed_cnt;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for squeeze state
    reg [$clog2(COEFF_WIDTH * N) : 0]   squeeze_cnt;    // counter for sampled coefficients
    reg [23:0]                          squeeze_buffer; //sampling buffer
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Algorithm 14: Coefficient generation from three bytes, FIPS 204 page 29, slide 39
    // Generates an element of {0, 1, 2, ..., q-1} from 3 bytes
    // Intput: Three bytes b0, b1, b2
    // Output: An integer in {0, 1, 2, ..., q-1} or sentinel (1s) if rejection occurs
    function [COEFF_WIDTH-1:0] CoeffFromThreeByte
        //input [7:0] b0, b1, b2;
        input [23:0] b2b1b0;
        reg [22:0]  z; 
        begin
            // z = {b2[6:0], b1, b0};
            z = b2b1b0[22:0];
            if (z < `Q)
                CoeffFromThreeByte = {1'b0, z}; //last bit is valid bit, 0 means valid 
            else 
                CoeffFromThreeByte = {COEFF_WIDTH{1'b1}}; //reject this sample, reset to full 1s and try again
        end
    endfunction

    wire [COEFF_WIDTH-1:0] current_coeff;
    assign current_coeff = CoeffFromThreeByte(squeeze_buffer);
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
                if (start) begin
                    next_state = ABSORB;
                end
            end
            ABSORB: begin
                if (in_ready && (feed_cnt + DATA_IN_BITS >= `SEED_SIZE)) begin 
                    //look ahead to make final clock update in_last and state
                    next_state = SQUEEZE;
                end
            end
            SQUEEZE: begin
                if (out_valid && (squeeze_cnt + COEFF_WIDTH == N * COEFF_WIDTH)) begin
                    next_state = IDLE;
                end
            end
        endcase
    end

    // ------------------------------------------------------------
    // Output / handshake signals
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            // Output signals
            done <= 0;
            poly <= 0;
            // shake256 signals
            data_in     <= 0;
            in_valid    <= 0;
            in_last     <= 0;
            out_ready   <= 0;
            // absorb signals
            feed_cnt    <= 0;
            // squeeze signals
            squeeze_cnt <= 0;
            squeeze_buffer <= 0;
        end else begin
            case (state)
                IDLE: begin
                    // Output signals
                    done <= 0;
                    poly <= 0;
                    // shake256 signals
                    data_in     <= 0;
                    in_valid    <= 1;
                    in_last     <= 0;
                    out_ready   <= 0;
                    // absorb signals
                    feed_cnt    <= 0;
                    // squeeze signals
                    squeeze_cnt <= 0;
                    squeeze_buffer <= 0;
                end
                ABSORB: begin
                    //34 * 8 = 272 < RATE = 1344 => absorb_block will never overflow
                    done <= 0;
                    in_valid <= 1;
                    if(in_ready) begin
                        data_in <= rho[feed_cnt +: DATA_IN_BITS];
                        feed_cnt <= feed_cnt + DATA_IN_BITS;

                        //send final block with in_last = 1
                        if(feed_cnt + DATA_IN_BITS >= `SEED_SIZE) begin
                            out_ready <= 1;
                            in_last <= 1;
                        end
                    end
                end
                SQUEEZE: begin
                    in_valid <= 0;
                    if(out_valid) begin
                        //reading output and calculate it into polynomial with rejection sampling
                        in_valid <= 0;
                        if(current_coeff[23] == 0) begin
                            poly[squeeze_cnt +: COEFF_WIDTH] = current_coeff;
                            squeeze_cnt <= squeeze_cnt + COEFF_WIDTH;
                        end
                        
                        //look ahead to notify done signal
                        if(squeeze_cnt + COEFF_WIDTH == N * COEFF_WIDTH) begin
                            done <= 1;
                        end
                    end
                end
            endcase
        end
    end

    sponge #(
        .LANE(64),
        .LANES(25),
        .STATE_W(1600),
        .STEP_RND(24),
        .CAPACITY(256), 
        .RATE(1344),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) shake128 (
        .clk(clk),
        .rst(rst),
        .data_in(data_in),
        .in_valid(in_valid),
        .in_last(in_last),
        .last_len(LAST_LEN),
        .out_ready(out_ready),
        .data_out(data_out),
        .out_valid(out_valid),
        .in_ready(in_ready)
    );
endmodule