`timescale 1ns / 1ps
// This should be described as a state in the Dilithium specification only
// Algorithm 34: Sampling the vector y, FIPS 204 page 38, slide 48
// Samples vector y in R_q^l with coefficients in [-gamma1 + 1, gamma1]
// Input: rho is a 64-byte seed, mu is a non-negative integer
// Output: Vector y of polynomials in R_q
//         Each entry is a polynomial (list of 256 coefficients mod q)

//SHALL NOT MODIFY THESE MACRO
#define SEED_SIZE 64 * 8
#define RHO_PRIME 66 * 8

module ExpandMask #(
    parameter int L = 7,
    parameter int N = 256,
    parameter int GAMMA1 = 19, // actually gamma1 = 2^this_parameter
    parameter int MAX_LOOPS = 814, //Appendix C - Loop Bounds for ML-DSA.Sign_internal
                                   //FIPS204, page 52, slide 62
    parameter int COEFF_WIDTH = GAMMA1 + 1,
    parameter int DATA_IN_BITS = 64,
    parameter int DATA_OUT_BITS = 64
) (
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,
    input  wire [`SEED_SIZE-1 : 0]          rho,
    input  wire [$clog2(L * MAX_LOOPS) : 0] mu,
    output reg                              done,
    output reg  [N * GAMMA1 - 1 : 0]        y[L]
);
    reg  [3 :0]                      cnt;
    wire [15:0]                      mu_plus_r;
    assign mu_plus_r = mu + cnt;
    reg  [$clog2(`SEED_SIZE) : 0]    feed_cnt;
    reg  
    // ------------------------------------------------------------
    // FSM state encoding
    localparam IDLE     = 2'd0;
    localparam ABSORB   = 2'd1;
    localparam SQUEEZE  = 2'd2;
    localparam UNPACK   = 2'd3;
    reg  [1:0] state, next_state;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for shake256 instance
    reg  [DATA_IN_BITS-1:0]                  data_in;
    reg                                      in_valid;
    reg                                      in_last;
    localparam int LAST_LEN = (`RHO_PRIME % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (`RHO_PRIME % DATA_IN_BITS);
    reg                                      out_ready;
    wire [DATA_OUT_BITS-1:0]                 data_out;
    wire                                     out_valid;
    wire                                     in_ready;
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
                if (in_ready && in_last) begin 
                    next_state = SQUEEZE;
                end
            end

            SQUEEZE: begin

            end

            UNPACK: begin
                if (done)
                    next_state = IDLE;
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            cnt <= 0;
            done <= 0;
            for (int i = 0; i < L; i++) y[i] <= 0;

            //shake signals
            data_in <= 0;
            in_valid <= 0;
            in_last <= 0;
            out_ready <= 0;
        end else begin
            case (state)
                IDLE: begin
                    cnt <= 0;
                    done <= 0;
                    for (int i = 0; i < L; i++) y[i] <= 0;

                    //shake signals
                    data_in <= 0;
                    in_valid <= 0;
                    in_last <= 0;
                    out_ready <= 0;
                end

                ABSORB: begin
                    //Total feed bits = 66 * 8 = 528 < 1088
                    if (in_ready) begin
                        if(feed_cnt >= `SEED_SIZE) begin
                            in_last <= 1;
                            data_in <= mu_plus_r;
                            out_ready <= 1;
                        end else begin
                            data_in <= rho[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                        end
                    end
                end

                SQUEEZE: begin
                    //Total squeeze data = 32 * c bytes = 32 * 20 * 8 = 5120 bit 
                    //=> permute 5 times 
                    if (out_valid) begin

                    end
                end

                UNPACK: begin
                end
            endcase
        end
    end

    //c = 1 + bitlen(gamma1-1) = COEFF_WIDTH
    //for r form 0 to (l-1)
        //rho' = rho||2bytes(mu+r)
        //v = SHAKE256(rho', 32 * c)
        //y[r] = BitUnPack(v, gamma-1, gamma1):
            //c = 20
            //for i from 0 to 255
            //y[r][i] = gamma1 - v[i*c +: c] 

    sponge #(
        .LANE(64),
        .LANES(25),
        .STATE_W(1600),
        .STEP_RND(24),
        .CAPACITY(512), 
        .RATE(1088),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(DATA_OUT_BITS)
    ) shake256 (
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