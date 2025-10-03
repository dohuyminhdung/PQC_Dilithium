`timescale 1ns / 1ps
// Algorithm 6: Key generation (see FIPS 204 page 23, slide 33)
// Generate a public - private key pair from a seed
// Input: a 32-byte random string xi
// Output: Public key pk, private key sk

module KeyGen_internal #(
    //ML-DSA87 parameters
    parameter int Q = 8380417,
    parameter int N = 256,
    parameter int K = 8,
    parameter int L = 7,
    parameter int ETA = 2,      //the bound for coefficients of secret vectors s1, s2
    parameter int D = 13,       //number of bits used for rounding during compression of polynomial coefficients.
    parameter int SEED_SIZE = 32 * 8,
    //RAM parameters
    parameter int WORD_WIDTH = 64,
    parameter int TOTAL_WORD = 4096,
    parameter int SEED_BASE_OFFSET = 0,         //rho'
    parameter int MATRIX_A_BASE_OFFSET = 0,     //matrixA 
    parameter int VECTOR_S_BASE_OFFSET = 0,     //vector s1, s2
    parameter int VECTOR_T_BASE_OFFSET = 0,     //public key t
    parameter int PUBLIC_KEY_BASE_OFFSET = 0,   //rho, t1
    parameter int SECRET_KEY_BASE_OFFSET = 0,   //rho, K, tr, s1.encode, s2.encode, t0
    //SHAKE parameters
    parameter int DATA_IN_BITS = 64,
    parameter int DATA_OUT_BITS = 64
    //other parameters
    parameter int COEFF_WIDTH = 24,
    parameter int COEFF_PER_WORD = 4,
    parameter int WORD_LEN = COEFF_PER_WORD * COEFF_WIDTH
)(
    //internal signals
    input  wire                     clk,
    input  wire                     rst,
    input  wire [SEED_SIZE-1:0]     xi,
    input  wire                     start,
    output reg                      done
    //RAM signals
    output reg                          ram_we_a,
    output reg  [$clog2(TOTAL_WORD):0]  ram_addr_a,
    output reg  [WORD_WIDTH-1:0]        ram_din_a,
    input  wire [WORD_WIDTH-1:0]        ram_dout_a,

    output reg                          ram_we_b,
    output reg  [$clog2(TOTAL_WORD):0]  ram_addr_b,
    output reg  [WORD_WIDTH-1:0]        ram_din_b,
    input  wire [WORD_WIDTH-1:0]        ram_dout_a,
    //SHAKE signals
    output reg                              shake_rst,
    output reg  [DATA_IN_BITS-1:0]          shake_data_in,
    input  wire                             shake_in_valid, 
    input  wire                             shake_in_last, 
    input  wire [$clog2(DATA_IN_BITS):0]    shake_last_len,
    input  wire                             shake_out_ready,   
    output reg  [DATA_OUT_BITS-1:0]         shake_data_out,
    output reg                              shake_out_valid,
    output reg                              shake_in_ready
);
    // FSM state encoding
    localparam IDLE             = 4'd0;
    
    localparam ABSORB_XI        = 4'd1;
    reg [$clog2(SEED_SIZE) : 0] feed_cnt;

    localparam SQUEEZE_SEED     = 4'd2;
    localparam EXPAND_A         = 4'd3;
    localparam EXPAND_S         = 4'd4;
    localparam CALCULATE_T_0    = 4'd5;    
    localparam CALCULATE_T_1    = 4'd6;
    localparam CALCULATE_T_2    = 4'd7;
    localparam CALCULATE_T_3    = 4'd8;
    localparam PK_ENCODE        = 4'd9;
    localparam SK_ENCODE        = 4'd10;
    reg  [3:0] state, next_state;        

    always @(posedge clk) begin
        if (rst) begin
            state <= IDLE;
        end else begin
            state <= next_state;
        end
    end

    always @* begin
        next_state = state
        case(state)
            IDLE: begin
                if(start)
                    next_state = ABSORB_XI;
            end
            ABSORB_XI: begin
            end
            SQUEEZE_SEED: begin
            end
            EXPAND_A: begin
            end
            EXPAND_S: begin
            end
            CALCULATE_T_0: begin
            end
            CALCULATE_T_1: begin
            end
            CALCULATE_T_2: begin
            end
            CALCULATE_T_3: begin
            end
            PK_ENCODE: begin
            end
            SK_ENCODE: begin
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
        end else begin
            case(state)
                IDLE: begin
                    if(start)
                        shake_rst <= 1;
                end
                ABSORB_XI: begin
                    shake_out_ready <= 0;
                    if(shake_in_ready) begin
                        shake_in_valid <= 1;
                        if(feed_cnt + DATA_IN_BITS < SEED_SIZE) begin
                            shake_data_in <= xi[feed_cnt +: DATA_IN_BITS];
                            feed_cnt <= feed_cnt + DATA_IN_BITS;
                            in_last <= 0;
                        end else begin
                            shake_data_in <= { (DATA_IN_BITS-16)'(0), 8'(K), 8'(L) };
                            feed_cnt <= 0;
                            in_last <= 1;
                        end 
                    end
                end
                SQUEEZE_SEED: begin
                    
                end
                EXPAND_A: begin
                end
                EXPAND_S: begin
                end
                CALCULATE_T_0: begin
                end
                CALCULATE_T_1: begin
                end
                CALCULATE_T_2: begin
                end
                CALCULATE_T_3: begin
                end
                PK_ENCODE: begin
                end
                SK_ENCODE: begin
                end
            endcase
        end
    end

endmodule