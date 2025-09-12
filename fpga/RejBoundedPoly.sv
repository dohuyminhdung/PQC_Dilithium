`timescale 1ns / 1ps

//DO NOT MODIFY THIS MACRO
`define RHO_SIZE 66*8 
`define BYTE 8

module RejBoundedPoly #(
    parameter int N   = 256,   
    parameter int ETA = 2,     
    parameter int COEFF_WIDTH = 4,
    parameter int DATA_IN_BITS = 64 //should divisible by 8
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             start,  //pulse 1 cycle        
    input  wire [RHO_SIZE-1 : 0]            rho,    //66 bytes         
    output reg                              done,        
    output reg [COEFF_WIDTH * N - 1 : 0]    poly_pack 
);

    reg [COEFF_WIDTH-1:0] poly [0:N-1]  poly;

    // ------------------------------------------------------------
    // FSM state encoding
    // ------------------------------------------------------------
    localparam IDLE     = 3'd0;
    localparam ABSORB   = 3'd1;
    localparam SQUEEZE  = 3'd2;

    reg  [1:0] state, next_state;

    // ------------------------------------------------------------
    // Signals for shake256 instance
    reg  [DATA_IN_BITS-1:0]                  data_in;
    reg                                      in_valid;
    reg                                      in_last;
    localparam int LAST_LEN = (RHO_SIZE % DATA_IN_BITS) == 0 ? DATA_IN_BITS : (RHO_SIZE % DATA_IN_BITS);
    reg                                      out_ready;
    wire [DATA_OUT_BITS-1:0]                 data_out;
    wire                                     out_valid;
    wire                                     in_ready;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for absorb state
    localparam int BLOCK_CNT = (RHO_SIZE + DATA_IN_BITS - 1) / DATA_IN_BITS;
    reg [$clog2(BLOCK_CNT)-1 : 0] feed_cnt;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Sequential state register
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            // Reset state
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
                if (out_valid) begin
                    next_state = SQUEEZE;
                end
            end
            SQUEEZE: begin
                if (done) begin
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
            block_cnt   <= 0;
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
                    block_cnt   <= 0;
                end
                ABSORB: begin
                    //66 * 8 = 528 < RATE = 1088 => kbh tran absorb_block
                    done <= 0;
                    out_ready <= 0;
                    in_valid <= 1;
                    if(in_ready) begin
                        data_in <= rho[feed_cnt * DATA_IN_BITS +: DATA_IN_BITS];
                        feed_cnt <= feed_cnt + 1;
                        if(feed_cnt == BLOCK_CNT) begin
                            in_last <= 1;
                            feed_cnt <= feed_cnt;
                        end
                    end
                    
                end
                SQUEEZE: begin

                end
            endcase
        end
    end

    sponge #(
        .LANE(64),
        .LANES(25),
        .STATE_W(1600),
        .STEP_RND(24),
        .CAPACITY(512), 
        .RATE(1088),
        .DATA_IN_BITS(DATA_IN_BITS),
        .DATA_OUT_BITS(BYTE)
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

    // -------------------------
    // Pack polynomial coefficients
    // -------------------------
    genvar gx, gy;
    generate
        for(gx=0; gx<N; gx= gx+1) begin: pack_coeff
            for(gy=0; gy<COEFF_WIDTH; gy=gy+1) begin: pack_bit
                assign poly_pack[gx*COEFF_WIDTH +: gy] = poly[gx][gy];
            end
        end
    endgenerate
endmodule

