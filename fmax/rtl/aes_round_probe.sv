// aes_round_probe.sv - reg -> one round stage -> reg, so synthesis times exactly one pipeline stage.
// Four fixed-parameter tops so the Genus script needs no -parameters syntax.
module aes_round_probe #(parameter int MODE = 1, parameter int SBOX_STYLE = 0) (
  input  logic         clk,
  input  logic         dir_i,
  input  logic [127:0] s_i,
  input  logic [127:0] rk_i,
  input  logic [7:0]   rcon_i,
  output logic [127:0] s_o,
  output logic [127:0] rk_o
);
  logic         dir_q;
  logic [127:0] s_q, rk_q, s_d, rk_d;
  logic [7:0]   rcon_q;
  always_ff @(posedge clk) begin
    dir_q <= dir_i; s_q <= s_i; rk_q <= rk_i; rcon_q <= rcon_i;
    s_o   <= s_d;   rk_o <= rk_d;
  end
  aes_round_stage #(.MODE(MODE), .SBOX_STYLE(SBOX_STYLE), .IS_LAST(1'b0)) u_stage (
    .dir(dir_q), .s_in(s_q), .rk_in(rk_q), .rcon(rcon_q), .s_out(s_d), .rk_out(rk_d));
endmodule

module probe_enc_lut     (input logic clk, dir_i, input logic [127:0] s_i, rk_i, input logic [7:0] rcon_i,
                          output logic [127:0] s_o, rk_o);
  aes_round_probe #(0, 0) u (.*);
endmodule
module probe_enc_tower   (input logic clk, dir_i, input logic [127:0] s_i, rk_i, input logic [7:0] rcon_i,
                          output logic [127:0] s_o, rk_o);
  aes_round_probe #(0, 1) u (.*);
endmodule
module probe_encdec_lut  (input logic clk, dir_i, input logic [127:0] s_i, rk_i, input logic [7:0] rcon_i,
                          output logic [127:0] s_o, rk_o);
  aes_round_probe #(1, 0) u (.*);
endmodule
module probe_encdec_tower(input logic clk, dir_i, input logic [127:0] s_i, rk_i, input logic [7:0] rcon_i,
                          output logic [127:0] s_o, rk_o);
  aes_round_probe #(1, 1) u (.*);
endmodule
