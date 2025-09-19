`timescale 1ns / 1ps
// rnd_core.v
// Keccak round core - 8-stage pipeline
// Stage summary (stage index là pipeline stage after posedge):
// 0: unpack/register input A0
// 1: theta stage1 -> compute C[x] (register C_reg)
// 2: theta stage2 -> compute D[x] (register D_reg)
// 3: theta stage3 -> apply D to A => A_theta (register A_theta)
// 4: rho stage -> rotate lanes => rho_reg
// 5: pi stage  -> permute lanes => pi_reg
// 6: chi stage1 -> compute T = (~B[x+1] & B[x+2]) (register T_reg)
// 7: chi stage2 + iota -> A_chi = B ^ T ; iota XOR rc into A_chi[0][0] => final_reg (state_out_reg)
// After stage7 state_out_reg is valid (out_valid asserted)

module rnd_core #(
    parameter LANE = 64,
    parameter LANES = 25,
    parameter STATE_W = LANE * LANES
)(
    input  wire                 clk,
    input  wire                 rst,      // synchronous reset (active high)
    input  wire                 en,       // enable pipeline (start new input when en=1)
    input  wire [STATE_W-1:0]   state_in, // 1600-bit flat input
    input  wire [LANE-1:0]      rc_in,    // 64-bit round constant (aligned by user to when en asserted)
    output reg  [STATE_W-1:0]   state_out,
    output reg                  out_valid
);

    // -------------------------
    // local indices
    // -------------------------
    integer x, y;

    // -------------------------
    // Helper: rotate left by n (0..63)
    // -------------------------
    function [LANE-1:0] rol;
        input [LANE-1:0] v;
        input integer   sh;
        begin
            // assume sh in 0..(LANE-1)
            rol = (v << sh) | (v >> (LANE - sh));
        end
    endfunction

    // -------------------------
    // Stage registers
    // -------------------------
    // Stage0: A0 (unpack from flat bus)
    reg [LANE-1:0] A0 [0:4][0:4];

    // Stage1: C_reg[x] (5 lanes)
    reg [LANE-1:0] C_reg [0:4];
    reg [LANE-1:0] A1 [0:4][0:4];

    // Stage2: D_reg[x] (5 lanes)
    reg [LANE-1:0] D_reg [0:4];
    reg [LANE-1:0] A2 [0:4][0:4];

    // Stage3: A_theta[x][y]
    reg [LANE-1:0] A_theta [0:4][0:4];

    // Stage4: rho_reg[x][y]
    reg [LANE-1:0] rho_reg [0:4][0:4];

    // Stage5: pi_reg[x][y]
    reg [LANE-1:0] pi_reg  [0:4][0:4];

    // Stage6: T_reg (chi partial) [x][y] = (~pi[...] & pi[...])
    reg [LANE-1:0] T_reg   [0:4][0:4];

    // Stage7: final_reg[x][y] after chi + iota
    reg [LANE-1:0] final_reg[0:4][0:4];

    // RC pipeline to align with stage7 (length = 8)
    reg [LANE-1:0] rc_pipe [0:7];

    // valid pipeline
    reg valid_pipe [0:7];
    
    //loop up table RHO_OFFSET [0][0:4] = '{ 0, 36, 3, 41, 18 } 
    localparam integer RHO_OFFSET [0:4][0:4] = '{
    '{  0, 36,  3, 41, 18 },
    '{  1, 44, 10, 45,  2 },
    '{ 62,  6, 43, 15, 61 },
    '{ 28, 55, 25, 21, 56 },
    '{ 27, 20, 39,  8, 14 }
    };

    // -------------------------
    // Unpack (Stage0) : register state_in into A0
    // -------------------------
    // layout chosen: bit-index mapping: lane index = (5*y + x), each lane is 64-bit slice
    always @(posedge clk) begin
        if (rst) begin
            for (x=0; x<5; x=x+1)
                for (y=0; y<5; y=y+1)
                    A0[x][y] <= {LANE{1'b0}};
                
            // clear pipelines
            for (x=0; x<5; x=x+1) C_reg[x] <= {LANE{1'b0}};
            for (x=0; x<5; x=x+1) D_reg[x] <= {LANE{1'b0}};
            for (x=0; x<5; x=x+1)
                for (y=0; y<5; y=y+1) begin
                    A1[x][y] <= {LANE{1'b0}};
                    A2[x][y] <= {LANE{1'b0}};
                    A_theta[x][y] <= {LANE{1'b0}};
                end
            for (x=0; x<5; x=x+1)
                for (y=0; y<5; y=y+1) begin
                    rho_reg[x][y] <= {LANE{1'b0}};
                    pi_reg[x][y]  <= {LANE{1'b0}};
                    T_reg[x][y]   <= {LANE{1'b0}};
                    final_reg[x][y] <= {LANE{1'b0}};
                end
            // rc_pipe & valid
            for (x=0; x<8; x=x+1) rc_pipe[x] <= {LANE{1'b0}};
            for (x=0; x<8; x=x+1) valid_pipe[x] <= 1'b0;
            out_valid <= 1'b0;
            state_out <= {STATE_W{1'b0}};
        end else begin
            // SHIFT rc pipeline and valid pipeline
            rc_pipe[0] <= rc_in;
            valid_pipe[0] <= en;
            for (x=1; x<8; x=x+1) begin
                rc_pipe[x] <= rc_pipe[x-1];
                valid_pipe[x] <= valid_pipe[x-1];
            end

            // Unpack only when en asserted => new data injected
            // Sample state_in only when en high.
            if (en) begin
                for (x=0; x<5; x=x+1) begin
                    for (y=0; y<5; y=y+1) begin
                        // little-endian lane ordering: lane index = 5*y + x
                        A0[x][y] <= state_in[64*(5*y + x) +: 64];
                    end
                end
            end else begin
                // if not en, propagate zeros or keep prior A0? choose to keep prior (no new input)
                // Here we keep prior A0 to avoid glitches.
                for (x=0; x<5; x=x+1)
                    for (y=0; y<5; y=y+1)
                        A0[x][y] <= A0[x][y];
            end

            // Stage1..Stage7 computations happen below (in order) - each stage reads previous stage regs
            // -------------------------
            // Stage1: compute C[x] = XOR_y A0[x][y]
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                    for (y=0; y<5; y=y+1) begin
                        A1[x][y] <= A0[x][y];
                    end
            end
            for (x=0; x<5; x=x+1) begin
                C_reg[x] <= A0[x][0] ^ A0[x][1] ^ A0[x][2] ^ A0[x][3] ^ A0[x][4];
            end
            
            // -------------------------
            // Stage2: compute D[x] = C[x-1] ^ rol(C[x+1],1)
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                // note index wrap-around: (x+4)%5 = x-1
                D_reg[x] <= C_reg[(x+4) % 5] ^ rol(C_reg[(x+1) % 5], 1);
            end
            for (x=0; x<5; x=x+1) begin
                    for (y=0; y<5; y=y+1) begin
                        A2[x][y] <= A1[x][y];
                    end
            end

            // -------------------------
            // Stage3: apply D: A_theta[x,y] = A0[x,y] ^ D_reg[x]
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                for (y=0; y<5; y=y+1) begin
                    A_theta[x][y] <= A2[x][y] ^ D_reg[x];
                end
            end

            // -------------------------
            // Stage4: rho: rotate lanes A_theta -> rho_reg
            // -------------------------
            // Do proper rotation offsets per (x,y).
            // rho_reg[x][y] <= rol(A_theta[x][y], rot_offset[x][y]);
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                for (y=0; y<5; y=y+1) begin
                    rho_reg[x][y] <= rol(A_theta[x][y], RHO_OFFSET[x][y]);
                end
            end

            // -------------------------
            // Stage5: pi: permute lanes rho_reg -> pi_reg
            // B[x,y] = rho_reg[(x+3*y)%5][x]
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                for (y=0; y<5; y=y+1) begin
                    pi_reg[x][y] <= rho_reg[(x + 3*y) % 5][x];
                end
            end

            // -------------------------
            // Stage6: chi part1: compute T = (~pi[(x+1),y]) & pi[(x+2),y]
            // register T_reg
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                for (y=0; y<5; y=y+1) begin
                    T_reg[x][y] <= (~pi_reg[(x+1)%5][y]) & pi_reg[(x+2)%5][y];
                end
            end

            // -------------------------
            // Stage7: chi part2 + iota: final = pi ^ T ; then iota: final[0][0] ^= rc_pipe[7]
            // -------------------------
            for (x=0; x<5; x=x+1) begin
                for (y=0; y<5; y=y+1) begin
                    final_reg[x][y] <= pi_reg[x][y] ^ T_reg[x][y];
                end
            end
            // apply iota using rc aligned to stage7
            final_reg[0][0] <= (pi_reg[0][0] ^ T_reg[0][0]) ^ rc_pipe[7];

            // -------------------------
            // Set out_valid from valid_pipe[7]
            // -------------------------
            out_valid <= valid_pipe[7];
        end
    end   
    
    // -------------------------
    // Update state_out
    // -------------------------
    genvar gx, gy;
    generate
        for (gx=0; gx<5; gx=gx+1) begin : pack_x
            for (gy=0; gy<5; gy=gy+1) begin : pack_y
                assign state_out[64*(5*gy + gx) +: 64] = final_reg[gx][gy];
            end
        end
    endgenerate

endmodule

