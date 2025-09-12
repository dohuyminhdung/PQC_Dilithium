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
    parameter DATA_OUT_BITS = 32 //The minimum squeezed data is 4 bytes
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
    reg  [$clog2(RATE):0]   absorb_block_cnt;
    reg  [RATE-1:0]         absorb_block;
    reg  [DATA_IN_BITS-1:0] absorb_data_in_buffer;
    wire [$clog2(RATE):0]   absorb_full;
    assign absorb_full = absorb_block_cnt + DATA_IN_BITS;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for Padding State
    reg  [$clog2(DATA_IN_BITS):0]   last_len_buffer;
    // ab=absorb_block, abc=absorb_block_cnt, dib=DATA_IN_BITS, llb=last_len_buffer, x=dont care
    // ab   = [0:abc-dib-1 ][0:llb-1][(dib-llb){x}][(RATE-abc){x}]
    // mask = [(abc-dib){1}][llb{1} ][(dib-llb){0}][(RATE-abc){0}] 
    wire [RATE-1:0] last_mask;
    assign last_mask = (absorb_block_cnt - DATA_IN_BITS + last_len_buffer) == 0 ? {RATE{1'b0}} :
                        ( { {RATE{1'b1}} } >> (RATE - (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) );                        
                        //(1 << (absorb_block_cnt - DATA_IN_BITS + last_len_buffer)) - 1;

    wire [RATE-1:0] msg_trimmed;
    assign msg_trimmed  = absorb_block & last_mask;
    
    // add bit '1' in padding 
    wire [RATE-1:0] padded;
    assign padded = msg_trimmed
              | (({{(RATE-1){1'b0}},1'b1}) << (absorb_block_cnt - DATA_IN_BITS + last_len_buffer))
              | (({{(RATE-1){1'b0}},1'b1}) << (RATE-1));
    // ------------------------------------------------------------
    
    // ------------------------------------------------------------
    // Signals for Squeezing State
    reg  [$clog2(RATE):0]   squeeze_block_cnt;
    wire [$clog2(RATE):0]   squeeze_out;
    assign squeeze_out = squeeze_block_cnt + DATA_OUT_BITS;
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    // Signals for Permutating State
    reg  [1:0] permute_mode, next_permute_mode; //00: absorb, 01: pad, 10: squeeze
    // wire start_permutation;
    // assign start_permutation = (state == ABSORB_DATA && in_valid && (absorb_full >= RATE))
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
        next_permute_mode = permute_mode;
        case (state)
            IDLE: begin
                next_state = ABSORB_DATA;
            end

            ABSORB_DATA: begin 
                if (!in_last) begin // clock sau moi bat dau cap nhat state => clock sau phai fill day block => abc + data_in >= RATE  
                    if (absorb_full >= RATE) begin
                        next_state = PERMUTE;
                        next_permute_mode = 2'b00; //absorb-permute
                    end
                end else begin  
                    if (absorb_block_cnt + last_len < RATE) begin //absorb_block_cnt + last_len < RATE => nhay den pad data
                        next_state = PAD_DATA;
                        next_permute_mode = 2'b10; //after pad permute -> go to squeeze
                    end else begin  //absorb_block_cnt + last_len = RATE => nhay den PERMUTE, set co pad data
                                    //absorb_block_cnt + last_len > RATE => kbh xay ra
                        next_state = PERMUTE;
                        next_permute_mode = 2'b01; //pad-only case
                    end
                end

            end

            PAD_DATA: begin 
                next_state = PERMUTE;
            end

            SQUEEZE_DATA: begin
                if (squeeze_out >= RATE) begin
                    next_state = PERMUTE;
                    next_permute_mode = 2'b10; //squeeze-permute 
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
            absorb_data_in_buffer <= 0;

            // Padding signals
            last_len_buffer <= 0;
            // Squeezing signals
            squeeze_block_cnt <= 0;
            // Permute signals
            permute_mode <= 0;
        end else begin 
            //keccak_en <= start_permutation;
            keccak_en <= 0;
            permute_mode <= next_permute_mode;
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
                    absorb_data_in_buffer <= 0;

                    // Padding signals
                    last_len_buffer <= 0;
                    // Squeezing signals
                    squeeze_block_cnt <= 0;
                    // Permute signals
                    permute_mode <= 0;
                end

                ABSORB_DATA: begin 
                    out_valid <= 0;
                    if (in_valid) begin
                        if (absorb_full < RATE) begin
                            absorb_block[absorb_block_cnt +: DATA_IN_BITS] <= data_in;
                            absorb_block_cnt <= absorb_full;
                            in_ready  <= 1;
                        end else begin
                            absorb_data_in_buffer <= data_in;
                            absorb_block_cnt <= 0;
                            state_reg <= state_reg ^ {absorb_block, {CAPACITY{1'b0}}};
                            keccak_en <= 1'b1; // START permute immediately (ABSORB full case)
                            in_ready  <= 0;
                        end
                    end
                    if (in_last) begin
                        last_len_buffer <= last_len;
                    end
                end

                PAD_DATA: begin
                    keccak_en <= 1'b1;
                    in_ready  <= 0;
                    out_valid <= 0;
                    case (permute_mode)
                        2'b10: begin
                            state_reg <= state_reg ^ {padded, {CAPACITY{1'b0}}};
                        end
                        2'b01: begin
                            state_reg <= state_reg ^ { {1'b1, {RATE-2{1'b0}}, 1'b1}, {CAPACITY{1'b0}} };
                        end
                    endcase
                end 

                SQUEEZE_DATA: begin
                    in_ready  <= 0;
                    out_valid <= 1;
                    if (out_ready) begin
                        data_out  <= state_reg[squeeze_block_cnt +: DATA_OUT_BITS];
                        squeeze_block_cnt <= squeeze_out;
                        if (squeeze_out >= RATE) begin
                           out_valid <= 1'b0;
                           keccak_en <= 1'b1; // start permute for next squeeze block
                        end
                    end
                end

                PERMUTE: begin
                    in_ready  <= 0;
                    out_valid <= 0;
                    if (keccak_done) begin
                        case (permute_mode)
                            2'b00: begin //absorb
                                absorb_block_cnt <= DATA_IN_BITS;
                                absorb_block[0 +: DATA_IN_BITS] <= absorb_data_in_buffer;
                                state_reg <= state_next;
                            end
                            2'b01: begin //padding
                                state_reg <= state_next;
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