`timescale 1ns / 1ps
module dp_ram_true #(
    parameter ADDR_WIDTH = 7,
    parameter DATA_WIDTH = 64,
    parameter INIT_FILE = ""
)(
    input  wire clk,
    // Port A
    input  wire                  we_a,
    input  wire [ADDR_WIDTH-1:0] addr_a,
    input  wire [DATA_WIDTH-1:0] din_a,
    output reg  [DATA_WIDTH-1:0] dout_a,
    // Port B
    input  wire                  we_b,
    input  wire [ADDR_WIDTH-1:0] addr_b,
    input  wire [DATA_WIDTH-1:0] din_b,
    output reg  [DATA_WIDTH-1:0] dout_b
);
    (* ram_style = "block" *) reg [DATA_WIDTH-1:0] mem [0:(1<<ADDR_WIDTH)-1];

    // Port A
    always @(posedge clk) begin
        if (we_a) mem[addr_a] <= din_a;
        dout_a <= mem[addr_a];
    end

    // Port B
    always @(posedge clk) begin
        if (we_b) mem[addr_b] <= din_b;
        dout_b <= mem[addr_b];  // synchronous read
    end

    initial begin
        if (INIT_FILE != "") begin
            $readmemh(INIT_FILE, mem);
        end
    end
endmodule