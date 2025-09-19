`timescale 1ns / 1ps

// Algorithm 29: Sampling the challenge polynomial c, FIPS 204 page 36, slide 46
// Samples a polynomial c in R_q with coefficients in {-1, 0, 1} and Hamming weight tau <= 64
// Input: rho (typically lambda/4 = 256/4 = 64 bytes from H(mu || w1Encode(w1)) in Sign)
// Output: A polynomial c in R_q (list of 256 coefficients in R_q)

module #( //CURRENTLY IMPLEMENTING ML-DSA-87 ONLY
    parameter int N = 256,                  // output are 256 coefficients from a polynomial
    parameter int LAMBDA = 256,             // collision strength of c~
    parameter int TAU = 60,                 // Hamming weight of c
    parameter int SEED_SIZE = LAMBDA/4*8,   // 64 bytes = 512 bits
    parameter int COEFF_WIDTH = 2,          // each coefficient is in range [-1; 1], represented by 2 bits
    parameter int DATA_IN_BITS = 64,        // shake256 input data bus width
    parameter int DATA_OUT_BITS = 64        // shake256 output data bus width
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle
    input  wire [SEED_SIZE-1 : 0]           rho,        //64 bytes
    output reg                              done,       //sampling done, pulse 1 cycle
    output reg  [COEFF_WIDTH * N - 1 : 0]   poly_pack   //packed polynomial output
)

    reg [COEFF_WIDTH-1:0] poly [0:N-1]; //raw polynomial output, compute in combinational logic

    // ------------------------------------------------------------
    // FSM state encoding
    localparam IDLE         = 2'd0;
    localparam ABSORB       = 2'd1;
    localparam PRE_SAMPLE   = 2'd2;
    localparam SAMPLING     = 2'd3;
    reg  [1:0] state, next_state;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for shake256 instance
    reg  [DATA_IN_BITS-1:0]                  data_in;
    reg                                      in_valid;
    reg                                      in_last;
    localparam int LAST_LEN = (SEED_SIZE % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (SEED_SIZE % DATA_IN_BITS);
    reg                                      out_ready;
    wire [DATA_OUT_BITS-1:0]                 data_out;
    wire                                     out_valid;
    wire                                     in_ready;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for absorb state
    reg [$clog2(SEED_SIZE) : 0] feed_cnt;
    // ------------------------------------------------------------
    
    // ------------------------------------------------------------
    // Signals for pre-sample state
    reg [63:0]                          pre_sample_buffer;  // buffer for pre-sampling (step 4 in Algorithm 29)
    reg                                 pre_sample_done;    // pre-sample state will squeeze 1 for step 4 and 1 more for next sampling state
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for sampling state
    reg [$clog2(DATA_OUT_BITS):0]   squeeze_cnt;        // counter for sampled coefficients
    reg [DATA_OUT_BITS-1:0]         squeeze_buffer1;    // main sampling buffer
    reg [DATA_OUT_BITS-1:0]         squeeze_buffer2;    // secondary sampling buffer 
    reg                             squeeze_refresh;    // flag to indicate squeeze_buffer2 is ready to be moved to squeeze_buffer1 
    reg [8:0]                       sample_cnt;         // counter for number of samples, 'i' in Algorithm 29
    reg [8:0]                       sample_cur;         // current sample value, 'j' in Algorithm 29
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
                if (in_ready && (feed_cnt + DATA_IN_BITS >= SEED_SIZE)) begin 
                    //look ahead to make final clock update in_last and state
                    next_state = PRE_SAMPLE;
                end
            end

            PRE_SAMPLE: begin
                if (out_valid && pre_sample_done) begin
                    next_state = SAMPLING;
                end
            end

            SAMPLING: begin
                if (squeeze_cnt >= N * COEFF_WIDTH) begin
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
            // pre-sample signals
            pre_sample_buffer <= 0;
            pre_sample_done <= 0;
            
            // sampling signals
            squeeze_cnt <= 0;
            squeeze_buffer <= 0;
            sample_cnt <= 256 - TAU;
            sample_cur <= 0;
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
                    // pre-sample signals
                    pre_sample_buffer <= 0;
                    pre_sample_done <= 0;

                    // sampling signals
                    squeeze_cnt <= 0;
                    squeeze_buffer <= 0;
                    sample_cnt <= 256 - TAU;
                    sample_cur <= 0;
                end
                ABSORB: begin
                    //64 * 8 = 512 < RATE = 1088 => absorb_block will never overflow
                    done <= 0;
                    in_valid <= 1;
                    if(in_ready) begin
                        data_in <= rho[feed_cnt +: DATA_IN_BITS];
                        feed_cnt <= feed_cnt + DATA_IN_BITS;

                        //send final block with in_last = 1
                        if(feed_cnt + DATA_IN_BITS >= SEED_SIZE) begin
                            out_ready <= 1;
                            in_last <= 1;
                        end
                    end
                end

                PRE_SAMPLE: begin
                    in_valid <= 0;
                    if(out_valid) begin
                        if (!pre_sample_done) begin
                            pre_sample_buffer <= data_out[0 +: 64]; //step 4: (ctx, s) <= H.Squeeze(ctx, 8 byte)
                            pre_sample_done <= 1;
                            squeeze_buffer1 <= data_out;
                            squeeze_cnt <= 64;
                        end else begin
                            //set up for squeeze state
                            squeeze_buffer2 <= data_out;
                            squeeze_refresh <= 1;
                            out_ready <= 0;
                            if(squeeze_cnt < DATA_OUT_BITS) begin
                                squeeze_cnt <= squeeze_cnt + 8;
                                sample_cur <= squeeze_buffer1[squeeze_cnt +: 8];
                            end
                        end
                    end
                end

                SAMPLING: begin
                    in_valid <= 0;

                    //sub-task squeezing new data, wait SHAKE256 permuting if it not ready, buffer1 may need to wait too 
                    if (out_valid && out_ready) begin 
                        squeeze_buffer2 <= data_out;
                        out_ready <= 0;
                        squeeze_refresh <= 1;
                    end
                    
                    if (squeeze_cnt >= DATA_OUT_BITS) begin
                        if (squeeze_refresh) begin
                            //squeeze_buffer1 is ready to be moved from squeeze_buffer2
                            out_ready <= 1;
                            squeeze_buffer1 <= squeeze_buffer2;
                            squeeze_cnt <= 8; //Actually it is: squeeze_cnt <= squeeze_cnt + 8 = 0 + 8 = 8
                            sample_cur <= squeeze_buffer2[0 +: 8];
                            squeeze_refresh <= 0;
                        end else begin
                            //need to wait for squeeze_buffer2 to be ready
                            out_ready <= 1;
                        end  
                    // step 6 for loop here
                    end else begin
                        //pre_sample_buffer = h = [63:0] H.Squeeze(64 bit)
                        //for i from (256 - TAU) = 196 to 255 do    => sample_cnt <= sample_cnt + 1
                            //j = H.Squeeze(8 bit)      => sample_cur <= squeeze_buffer1[squeeze_cnt +: 8]
                            //while j > i do            => if(sample_cur > sample_cnt)
                            //    j = H.Squeeze(8 bit)  => squeeze_cnt <= squeeze_cnt + 8
                            //c[i] = c[j]               => poly[sample_cnt] <= poly[sample_cur]
                            //c[j] = -1^{h[i+TAU-256]}  => poly[sample_cur] <= pre_sample_buffer[i + 60 - 256] ? -1 : 1
                        if (sample_cur > sample_cnt) begin
                            sample_cur <= squeeze_buffer1[squeeze_cnt +: 8];
                            squeeze_cnt <= squeeze_cnt + 8;
                        end else begin
                            poly[sample_cnt] <= poly[sample_cur];
                            poly[sample_cur] <= pre_sample_buffer[i + TAU - 256] ? 2'b11 : 2'b01;
                            sample_cnt <= sample_cnt + 1;
                            if (sample_cnt + 1 >= 255) begin
                                done <= 1;
                            end
                        end
                    end
                end
            endcase
        end
    end

    // -------------------------
    // Pack output polynomial coefficients
    genvar gx;
    generate
        for(gx=0; gx<N; gx= gx+1) begin: pack_coeff
            poly_pack[gx*COEFF_WIDTH +: COEFF_WIDTH] = poly[gx];
        end
    endgenerate
    // -------------------------

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
 