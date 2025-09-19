`timescale 1ns / 1ps

// Algorithm 31: Rejection sampling, FIPS 204 page 37, slide 47
// Samples a polynomial in R_q with coefficients in [-eta, eta]
// Input: seed (typically 66 bytes from (rho' || 2 bytes in ExpandS))
// Output: An element in R_q with coefficients in [-eta, eta] (list of 256 coefficients in R_q)

//SHALL NOT MODIFY THESE MACRO
`define SEED_SIZE 66*8 
`define BYTE 8

module RejBoundedPoly #( //CURRENTLY IMPLEMENTING ML-DSA-87 ONLY
    parameter int N   = 256,         // output are 256 coefficients from a polynomial   
    parameter int ETA = 2,           // private key range in Dilithium
    parameter int COEFF_WIDTH = 4,   // coefficient is guarantee in range [-eta, eta] = [-2, 2]
    parameter int DATA_IN_BITS = 64, //should divisible by 8
    parameter int DATA_OUT_BITS = 64 //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,      //pulse 1 cycle        
    input  wire [`SEED_SIZE-1 : 0]          rho,        //66 bytes         
    output reg                              done,       //sampling done, pulse 1 cycle     
    output reg  [COEFF_WIDTH * N - 1 : 0]   poly_pack   //packed polynomial output
);

    wire [COEFF_WIDTH-1:0] poly [0:N-1]; //raw polynomial output, compute in combinational logic

    // ------------------------------------------------------------
    // FSM state encoding
    localparam IDLE     = 2'd0;
    localparam ABSORB   = 2'd1;
    localparam SQUEEZE  = 2'd2;
    reg  [1:0] state, next_state;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for shake256 instance
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
    reg [$clog2(N * `BYTE) : 0]     squeeze_cnt;   //need to squeeze total of 256 bytes.
    reg [N * `BYTE - 1 : 0]         squeeze_buffer; //squeeze 256 bytes buffer
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Algorithm 15: Coefficient generation from a half byte, FIPS 204 page 30, slide 40
    // Generates an element of {-eta, ..., eta} from a half byte
    // Input:  A half byte b (0 <= b < 16)
    // Output: A 2’s complement 4 bits number in {-eta, ..., eta}, currently only support eta = 2 (ML-DSA87)
    function [COEFF_WIDTH-1:0] CoeffFromHalfByte
        input [3:0] b;
        begin
            case (b)
                4'd0:   CoeffFromHalfByte =  4'b0010; //2
                4'd1:   CoeffFromHalfByte =  4'b0001; //1
                4'd2:   CoeffFromHalfByte =  4'b0000; //0
                4'd3:   CoeffFromHalfByte =  4'b1111; //-1
                4'd4:   CoeffFromHalfByte =  4'b1110; //-2
                4'd5:   CoeffFromHalfByte =  4'b0010; //2
                4'd6:   CoeffFromHalfByte =  4'b0001; //1
                4'd7:   CoeffFromHalfByte =  4'b0000; //0
                4'd8:   CoeffFromHalfByte =  4'b1111; //-1
                4'd9:   CoeffFromHalfByte =  4'b1110; //-2
                4'd10:  CoeffFromHalfByte =  4'b0010; //2
                4'd11:  CoeffFromHalfByte =  4'b0001; //1
                4'd12:  CoeffFromHalfByte =  4'b0000; //0
                4'd13:  CoeffFromHalfByte =  4'b1111; //-1
                4'd14:  CoeffFromHalfByte =  4'b1110; //-2
                4'd15:  CoeffFromHalfByte =  4'b0010; //2
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
                if (out_valid && (squeeze_cnt + DATA_OUT_BITS >= N * `BYTE)) begin
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
                    //66 * 8 = 528 < RATE = 1088 => absorb_block will never overflow
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
                        //reading output and calculate it into polynomial
                        squeeze_buffer[squeeze_cnt +: DATA_OUT_BITS] <= data_out;
                        squeeze_cnt <= squeeze_cnt + DATA_OUT_BITS;
                        
                        //lookup to check if squeeze enough data
                        if(squeeze_cnt + DATA_OUT_BITS >= N * `BYTE) begin //2048
                            done <= 1;
                            out_ready <= 0;
                        end
                    end
                end
            endcase
        end
    end

    // -------------------------
    // Calculate polynomial from squeeze_buffer
    genvar i;
    for (i = 0; i < N; i = i + 1) begin: calc_poly
        assign poly[i] = CoeffFromHalfByte(squeeze_buffer[i * `BYTE +: 4]);
    end
    // -------------------------

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

