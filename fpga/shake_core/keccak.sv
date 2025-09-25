`timescale 1ns / 1ps
// ----------------------------------------------------------------------
// keccak_p.v
// Keccak-p permutation iterative
// ----------------------------------------------------------------------
module keccak_p #(
    parameter LANE = 64,
    parameter LANES = 25,
    parameter STATE_W = LANE * LANES,
    parameter STEP_RND = 24
)(
    input   wire                    clk,
    input   wire                    rst,
    input   wire                    en,
    input   wire    [STATE_W-1:0]   state_in,
    output  reg     [STATE_W-1:0]   state_out,
    output  reg                     out_valid
    );
    
    // ------------------------------------------------------------
    // Local RC table
    // ------------------------------------------------------------
    localparam [LANE-1:0] RC [0:23] = '{
        64'h0000000000000001, 64'h0000000000008082, 64'h800000000000808A, 
        64'h8000000080008000, 64'h000000000000808B, 64'h0000000080000001,
        64'h8000000080008081, 64'h8000000000008009, 64'h000000000000008A, 
        64'h0000000000000088, 64'h0000000080008009, 64'h000000008000000A,
        64'h000000008000808B, 64'h800000000000008B, 64'h8000000000008089, 
        64'h8000000000008003, 64'h8000000000008002, 64'h8000000000000080,
        64'h000000000000800A, 64'h800000008000000A, 64'h8000000080008081, 
        64'h8000000000008080, 64'h0000000080000001, 64'h8000000080008008
    };
    
    reg                         active; 
    reg  [$clog2(STEP_RND)-1:0] step_cnt;  
    reg                         rnd_en;
    wire                        rnd_done;
    reg  [STATE_W-1:0]          state_reg;
    wire [STATE_W-1:0]          state_next;

    always @(posedge clk) begin
        if (rst) begin
            state_out <= 0;
            out_valid <= 0;
            active    <= 0;
            step_cnt  <= 0;
            rnd_en    <= 0;
            state_reg <= 0;
        end else if (en) begin
            state_out <= 0;
            out_valid <= 0;
            active    <= 1;
            step_cnt  <= 0;
            rnd_en    <= 1;
            state_reg <= state_in;
        end else if (active) begin //en = 0, active = 1 => running
            if (rnd_done) begin
                state_reg <= state_next;
                if (step_cnt == STEP_RND-1) begin
                    active <= 0;
                    out_valid <= 1;
                    state_out <= state_next;
                end else begin
                    step_cnt  <= step_cnt + 1;
                    rnd_en    <= 1;
                end
            end else begin
                rnd_en <= 0;
            end
        end else begin //en = 0, active = 0 => wait en = 1, keep out_valid = 0
            rnd_en    <= 0;
            out_valid <= 0;
        end
    end
    
    wire [LANE-1:0] rc_sel;
    assign rc_sel = RC[step_cnt];
    
    rnd_core #(
        .LANE    (LANE),
        .LANES   (LANES),
        .STATE_W (STATE_W)
        ) u_rnd (
                .clk       (clk),
                .rst       (rst),
                .en        (rnd_en),
                .state_in  (state_reg),
                .rc_in     (rc_sel),
                .state_out (state_next),
                .out_valid (rnd_done)
            );    
endmodule
