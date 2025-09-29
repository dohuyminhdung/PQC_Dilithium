`timescale 1ns / 1ps
//Input:
//in_valid announce that data_in is a valid data, note that not all cycle we do feed data to the module
//in_last announce that this data_in is the last block, we need to pad this data_in if needed
//last_len notify the len of last block
//out_ready announce that user is ready to get the squeezed data
//Output:
//out_valid announe that data_out is a valid data, note that not all cycle the module have the squeezed data
//in_ready announce that the module is ready to accept new data, note that while absorbing data, the module may not be ready to accept new data
module sponge #(
    parameter LANE          = 64,
    parameter LANES         = 25,
    parameter STATE_W       = LANE * LANES,
    parameter STEP_RND      = 24,
    parameter CAPACITY      = 512, //default is SHAKE256/SHA3-256
    parameter RATE          = STATE_W - CAPACITY,
    parameter DATA_IN_BITS  = 64,
    parameter DATA_OUT_BITS = 64 
)(
    input  wire                             clk,
    input  wire                             rst,
    input  wire [DATA_IN_BITS-1:0]          data_in,
    input  wire                             in_valid, 
    input  wire                             in_last, 
    input  wire [$clog2(DATA_IN_BITS):0]    last_len,
    input  wire                             out_ready,   
    output reg  [DATA_OUT_BITS-1:0]         data_out,
    output reg                              out_valid,
    output reg                              in_ready
    );
    // ------------------------------------------------------------
    // FSM state encoding
    // ------------------------------------------------------------
    localparam IDLE             = 3'd0;
    localparam ABSORB_DATA      = 3'd1;
    localparam PAD_DATA         = 3'd2;
    localparam SQUEEZE_DATA     = 3'd3;
    localparam PERMUTE          = 3'd4;

    reg  [2:0] state, next_state;

    // ------------------------------------------------------------
    // Signals for keccak instance
    reg                     keccak_en;
    reg  [STATE_W-1:0]      state_reg;
    wire [STATE_W-1:0]      state_next;
    wire                    keccak_done;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for Absorbing State
    reg  [$clog2(RATE)-1:0] absorb_block_cnt;
    reg  [RATE-1:0]         absorb_block;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for Padding State
    reg  [$clog2(DATA_IN_BITS):0]   last_len_buffer;
    reg                             overflow;           // indicate that the last padding operation cause overflow
    reg                             overflow_last_pad;  // last padding before squeeze if overflow

    //ab=absorb_block, abc=absorb_block_cnt, dib=DATA_IN_BITS, llb=last_len, x=dont care    
    // Normal case:
    // expect:  [10*1][1111]     [ll-1:0](di)[abc-dib-1:0](ab)
    // ab    =  [(RATE-abc){x}]  [abc-1:0](ab)
    // mask0 =  [(RATE-(abc-dib+ll)){0}][(abc-dib+ll){1}]
    // mask1 =  1[(RATE-(abc-dib+ll-6)){0}]1[1111][(abc-dib+ll){0}]
    wire [RATE-1:0] pad_mask_0s;
    assign pad_mask_0s = (absorb_block_cnt - DATA_IN_BITS + last_len_buffer) == 0 ? {RATE{1'b0}} :
                        ( { {RATE{1'b1}} } >> (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) );                        
                        //(1 << (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) - 1;

    wire [RATE-1:0] msg_trimmed;
    assign msg_trimmed  = absorb_block & pad_mask_0s;

    wire [RATE-1:0] pad_mask_first_1s;
    assign pad_mask_first_1s = ({{(RATE-5){1'b0}},5'b11111}) << (absorb_block_cnt - DATA_IN_BITS + last_len_buffer);

    wire [RATE-1:0] pad_mask_last_1s; 
    assign pad_mask_last_1s = ({{(RATE-1){1'b0}},1'b1}) << (RATE-1);

    wire [RATE-1:0] no_overflow_case = (overflow && (absorb_block_cnt == RATE)) ?
                                        msg_trimmed : 
                                        msg_trimmed | pad_mask_first_1s | pad_mask_last_1s;
    
    // Overflow case:
    //1st: append (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) 1s => same as normal padding
    //2nd  5 - (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) 1s + 0* + 1
    // RATE * {1} >> RATE - (5 - (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)))
    wire [RATE-1:0] pad_mask_left_1s;
    assign pad_mask_left_1s = ({(RATE){1'b1}}) >> (RATE - (5 - (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer))));

    wire [RATE-1:0] overflow_case;
    assign overflow_case = ({(RATE){1'b0}}) | pad_mask_left_1s | pad_mask_last_1s;

    wire [RATE-1:0] padded;
    assign padded = (!overflow | !overflow_last_pad) ? no_overflow_case : overflow_case;
                    // msg_trimmed
                    // | (({{(RATE-5){1'b0}},5'b11111}) << (absorb_block_cnt - DATA_IN_BITS + last_len_buffer))
                    // | (({{(RATE-1){1'b0}},1'b1}) << (RATE-1)) :
                    // ({(RATE){1'b0}})
                    // | (({(RATE){1'b1}}) >> (RATE - (5 - (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)))))
                    // | (({{(RATE-1){1'b0}},1'b1}) << (RATE-1));
    // ------------------------------------------------------------
    
    // ------------------------------------------------------------
    // Signals for Squeezing State
    reg  [$clog2(RATE)-1:0]   squeeze_block_cnt;
    wire [$clog2(RATE)-1:0]   squeeze_out;
    assign squeeze_out = squeeze_block_cnt + DATA_OUT_BITS;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for Permutating State
    reg  [1:0] permute_mode, post_permute_mode; //00: absorb, 01: pad, 10: squeeze
    // wire start_permutation;
    // assign start_permutation = (state == ABSORB_DATA && in_valid && (absorb_block_cnt >= RATE))
    //                         || (state == PAD_DATA)
    //                         || (state == SQUEEZE_DATA && squeeze_out >= RATE);
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
        post_permute_mode = permute_mode;
        case (state)
            IDLE: begin
                next_state = ABSORB_DATA;
            end

            ABSORB_DATA: begin 
                if (in_valid && !in_last) begin
                    if (absorb_block_cnt >= RATE) begin
                        next_state = PERMUTE;
                        post_permute_mode = 2'b00; //absorb-permute
                    end
                end else if(in_valid && in_last) begin  
                    next_state = PAD_DATA;
                end

            end

            PAD_DATA: begin 
                next_state = PERMUTE;
                case (overflow)
                    1'b0: post_permute_mode = 2'b10; //after pad permute -> go to squeeze
                    1'b1: begin
                        if(overflow_last_pad == 0)
                            post_permute_mode = 2'b01; //after pad permute -> go to pad again
                        else
                            post_permute_mode = 2'b10; //after last pad permute -> go to squeeze
                    end
                endcase
            end

            SQUEEZE_DATA: begin
                if (squeeze_out >= RATE) begin
                    next_state = PERMUTE;
                    post_permute_mode = 2'b10; //squeeze-permute 
                end
            end        

            PERMUTE: begin
                if (keccak_done) begin
                    case (permute_mode)
                        2'b00: next_state = ABSORB_DATA; //absorb
                        2'b01: next_state = PAD_DATA; //padding
                        2'b10: next_state = SQUEEZE_DATA; //squeeze
                        default: next_state = IDLE;
                    endcase
                end
            end

            default: next_state = IDLE;
        endcase
    end

    // ------------------------------------------------------------
    // Output / handshake signals
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin      
            // Output signals
            data_out    <= 32'hDEADCAFE;
            out_valid   <= 1'b0;
            in_ready    <= 1'b1;

            // keccak instance signals
            keccak_en <= 0;
            state_reg <= 0;

            // Absorbing signals
            absorb_block_cnt <= 0;
            absorb_block <= 0;

            // Padding signals
            last_len_buffer <= 0;
            overflow     <= 0;
            overflow_last_pad <= 0;

            // Squeezing signals
            squeeze_block_cnt <= 0;
            // Permute signals
            permute_mode <= 0;
        end else begin 
            //keccak_en <= start_permutation;
            permute_mode <= post_permute_mode;
            case (state)
                IDLE: begin
                    // Output signals
                    data_out    <= 32'hDEADBEEF;
                    out_valid   <= 1'b0;
                    in_ready    <= 1'b1;

                    // keccak instance signals
                    keccak_en <= 0;
                    state_reg <= 0;

                    // Absorbing signals
                    absorb_block_cnt <= 0;
                    absorb_block <= 0;

                    // Padding signals
                    last_len_buffer <= 0;
                    overflow     <= 0;
                    overflow_last_pad <= 0;

                    // Squeezing signals
                    squeeze_block_cnt <= 0;
                end

                ABSORB_DATA: begin 
                    out_valid <= 0;
                    if (in_valid) begin
                        if (absorb_block_cnt < RATE) begin
                            absorb_block[absorb_block_cnt +: DATA_IN_BITS] <= data_in;
                            absorb_block_cnt <= absorb_block_cnt + DATA_IN_BITS;
                            keccak_en <= 0;
                            in_ready  <= 1;
                        end else begin
                            absorb_block_cnt <= 0;
                            state_reg <= state_reg ^ {{CAPACITY{1'b0}}, absorb_block};
                            keccak_en <= 1'b1; // START permute immediately (ABSORB full case)
                            in_ready  <= 0;
                        end

                        if (absorb_block_cnt + DATA_IN_BITS >= RATE) begin
                            in_ready  <= 0; //look ahead adding final block, full => next clock will set up for permute
                        end
                        
                        if (in_last) begin //look ahead for next padding state
                            last_len_buffer <= last_len;
                            if (absorb_block_cnt + last_len + 6 > RATE) begin //padding => permute => padding => permute => squeeze
                                overflow <= 1;
                                overflow_last_pad <= 0;
                            end else begin //else padding => permute => squeeze
                                overflow <= 0;
                            end
                        end
                    end  
                end

                PAD_DATA: begin
                    keccak_en <= 1'b1;
                    in_ready  <= 0;
                    out_valid <= 0;
                    state_reg <= state_reg ^ {{CAPACITY{1'b0}}, padded};
                end 

                SQUEEZE_DATA: begin
                    in_ready  <= 0;
                    if (out_ready) begin
                        out_valid <= 1;
                        data_out  <= state_reg[squeeze_block_cnt +: DATA_OUT_BITS];
                        squeeze_block_cnt <= squeeze_out;
                        if (squeeze_out >= RATE) begin
                           //out_valid <= 1'b0;
                           keccak_en <= 1'b1; // start permute for next squeeze block
                        end
                    end
                end

                PERMUTE: begin
                    in_ready  <= 1'b0;
                    out_valid <= 1'b0;
                    keccak_en <= 1'b0; 
                    if (keccak_done) begin
                        case (permute_mode)
                            2'b00: begin //absorb
                                state_reg <= state_next;
                                // absorb_block_cnt <= 0; //already do in PAD_DATA look ahead ABSORB_DATA
                            end
                            2'b01: begin //padding
                                state_reg <= state_next;
                                if (overflow && !overflow_last_pad)
                                    overflow_last_pad <= 1;
                                // absorb_block_cnt <= 5 - (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer));
                            end
                            2'b10: begin //squeeze 
                                state_reg <= state_next;
                                squeeze_block_cnt <= 0;
                            end
                            default: state_reg <= state_next;
                        endcase
                    end
                end
            endcase
        end
    end

    keccak_p #(
        .LANE       (LANE),
        .LANES      (LANES),
        .STATE_W    (STATE_W),
        .STEP_RND   (STEP_RND)
    ) keccak_instance (
        .clk        (clk),
        .rst        (rst),
        .en         (keccak_en),
        .state_in   (state_reg),          
        .state_out  (state_next),
        .out_valid  (keccak_done)
    );

endmodule