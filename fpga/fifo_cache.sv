`timescale 1ns / 1ps

function automatic integer gcd;
    input integer x, y;
    begin
      while (y != 0) begin
        int temp = y;
        y = x % y;
        x = temp;
      end
      gcd = x;
    end
endfunction


module fifo_cache #(
    parameter DATA_WR_WIDTH = 64, 
    parameter DATA_RD_WIDTH = 20,
    parameter WORD = gcd(DATA_WR_WIDTH, DATA_RD_WIDTH),
    parameter DEPTH = 256
) (
    input  wire                             clk,
    input  wire                             rst,
    input  wire                             rd,
    input  wire                             wr,
    input  wire [DATA_WR_WIDTH-1:0]         data_in, 
    input  wire [$clog2(DATA_WR_WIDTH)-1:0] data_in_width,
    output wire                             empty, 
    output wire                             full,
    output reg  [DATA_RD_WIDTH-1:0]         data_out
    ); 
    localparam ADDR_WIDTH = $clog2(DEPTH);
    localparam PUSH_SIZE  = DATA_WR_WIDTH / WORD;
    localparam POP_SIZE   = DATA_RD_WIDTH / WORD;

    reg [WORD-1:0] mem [DEPTH-1:0]; 

    reg  [ADDR_WIDTH:0]  wrpt, rdpt;
    wire [ADDR_WIDTH:0]  usedw;
    assign usedw = wrpt - rdpt;
    assign full  = (usedw + PUSH_SIZE > DEPTH);
    assign empty = (usedw < POP_SIZE);

    wire wren = wr && !full;
    wire rden = rd && !empty;

    //write port
    always @(posedge clk) begin
        if (rst) begin
            wrpt <= 0;
        end else if (wren) begin
            integer i;
            integer first, second;
            first = (wrpt[ADDR_WIDTH-1:0] + data_in_width <= DEPTH) ? data_in_width : (DEPTH - wrpt[ADDR_WIDTH-1:0]);
            second = data_in_width - first;

            //main segment
            for (i = 0; (i < first) && (i < PUSH_SIZE); i = i + 1) 
                mem[wrpt[ADDR_WIDTH-1:0] + i] <= data_in[WORD*i +: WORD];
            //wrap-around
            for (i = 0; (i < second) && (i < PUSH_SIZE); i = i + 1)
                mem[i] <= data_in[WORD*(first+i) +: WORD];

            wrpt <= wrpt + (data_in_width / WORD);
        end
    end

    //read port
    always @(posedge clk) begin
        if (rst) begin
            rdpt <= 0;
            data_out <= 0;
        end else if (rden) begin
            integer i;
            integer first, second;
            first = (rdpt[ADDR_WIDTH-1:0] + POP_SIZE <= DEPTH) ? POP_SIZE : (DEPTH - rdpt[ADDR_WIDTH-1:0]);
            second = POP_SIZE - first;

            for (i = 0; (i < first) && (i < POP_SIZE); i = i + 1) 
                data_out[WORD*i +: WORD] <= mem[rdpt[ADDR_WIDTH-1:0] + i];
            for (i = 0; (i < second) && (i < POP_SIZE); i = i + 1)
                data_out[WORD*(first+i) +: WORD] <= mem[i];
            
            rdpt <= rdpt + POP_SIZE; 
        end
    end
endmodule