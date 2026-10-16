// tb_round.sv - chains the combinational round stage 10x for full AES-128 enc and dec,
// all 4 configs, against golden vectors; exhaustive S-box check; probe register check.
`timescale 1ns/1ps
module tb_round;
  import aes_sbox_pkg::*;
  localparam int NV = `ifdef NV_OVR `NV_OVR `else 303 `endif;
  logic [511:0] vec [0:NV-1];      // {key, rk10, pt, ct}
  logic [15:0]  sx  [0:255];       // {sbox, inv sbox}
  function automatic logic [7:0] RCON(input int i);
    logic [7:0] t [10];
    t[0]=8'h01; t[1]=8'h02; t[2]=8'h04; t[3]=8'h08; t[4]=8'h10; t[5]=8'h20; t[6]=8'h40; t[7]=8'h80; t[8]=8'h1b; t[9]=8'h36;
    return t[i];
  endfunction
  int errors = 0;

  // 4 configs x {middle, last} stages, shared stimulus
  logic         dir;
  logic [127:0] s_in, rk_in;
  logic [7:0]   rcon;
  logic [127:0] s_m [4], rk_m [4], s_l [4], rk_l [4];
  `define STG(i, M, S) \
    aes_round_stage #(.MODE(M), .SBOX_STYLE(S), .IS_LAST(0)) m``i (.dir(dir), .s_in(s_in), .rk_in(rk_in), .rcon(rcon), .s_out(s_m[i]), .rk_out(rk_m[i])); \
    aes_round_stage #(.MODE(M), .SBOX_STYLE(S), .IS_LAST(1)) l``i (.dir(dir), .s_in(s_in), .rk_in(rk_in), .rcon(rcon), .s_out(s_l[i]), .rk_out(rk_l[i]));
  `STG(0, 0, 0)
  `STG(1, 0, 1)
  `STG(2, 1, 0)
  `STG(3, 1, 1)
  function automatic string NAME(input int i);
    case (i) 0: return "enc_lut"; 1: return "enc_tower"; 2: return "encdec_lut"; default: return "encdec_tower"; endcase
  endfunction

  task automatic run_block(input int cfg, input logic d, input logic [127:0] key, rk10, din, output logic [127:0] dout);
    logic [127:0] s, rk;
    dir = d;
    if (!d) begin
      s = din ^ key; rk = key;
      for (int r = 1; r <= 10; r++) begin
        s_in = s; rk_in = rk; rcon = RCON(r-1); #1;
        s  = (r == 10) ? s_l[cfg]  : s_m[cfg];
        rk = (r == 10) ? rk_l[cfg] : rk_m[cfg];
      end
    end else begin
      s = din ^ rk10; rk = rk10;
      for (int r = 9; r >= 0; r--) begin
        s_in = s; rk_in = rk; rcon = RCON(r); #1;
        s  = (r == 0) ? s_l[cfg]  : s_m[cfg];
        rk = (r == 0) ? rk_l[cfg] : rk_m[cfg];
      end
      if (rk !== key) begin errors++; $display("FAIL %s inverse key schedule did not return to K", NAME(cfg)); end
    end
    dout = s;
  endtask

  // probe wrapper: one encrypt round through registers
  logic clk = 0; always #5 clk = ~clk;
  logic [127:0] po_s, po_rk;
  probe_encdec_tower u_probe (.clk(clk), .dir_i(1'b0), .s_i(s_in), .rk_i(rk_in), .rcon_i(rcon), .s_o(po_s), .rk_o(po_rk));

  initial begin
    logic [127:0] out, exp_s;
    int bad, be, bd;
    $readmemh("aes_blocks.hex", vec);
    $readmemh("sbox_expect.hex", sx);
    bad = 0;
    for (int x = 0; x < 256; x++)
      if (sbox_lut(x) !== sx[x][15:8] || isbox_lut(x) !== sx[x][7:0] || sbox_tower(x) !== sx[x][15:8] ||
          sbox_tower_ed(x, 1'b0) !== sx[x][15:8] || sbox_tower_ed(x, 1'b1) !== sx[x][7:0]) bad++;
    $display("%s  S-box exhaustive (LUT, tower, tower shared enc/dec): %0d/256 wrong", bad ? "FAIL" : "PASS", bad);
    errors += bad;
    for (int cfg = 0; cfg < 4; cfg++) begin
      be = 0; bd = 0;
      for (int v = 0; v < NV; v++) begin
        run_block(cfg, 1'b0, vec[v][511:384], vec[v][383:256], vec[v][255:128], out);
        if (out !== vec[v][127:0]) be++;
        if (cfg >= 2) begin
          run_block(cfg, 1'b1, vec[v][511:384], vec[v][383:256], vec[v][127:0], out);
          if (out !== vec[v][255:128]) bd++;
        end
      end
      if (cfg >= 2) $display("%s  %-13s encrypt %0d/%0d   decrypt %0d/%0d", (be + bd) ? "FAIL" : "PASS", NAME(cfg), NV - be, NV, NV - bd, NV);
      else          $display("%s  %-13s encrypt %0d/%0d", be ? "FAIL" : "PASS", NAME(cfg), NV - be, NV);
      errors += be + bd;
    end
    // probe: round 1 of FIPS vector through registers (2 clock edges)
    dir = 0; s_in = vec[0][255:128] ^ vec[0][511:384]; rk_in = vec[0][511:384]; rcon = 8'h01;
    #1; begin
      exp_s = s_m[3];
      repeat (3) @(posedge clk); #1;
      if (po_s !== exp_s) begin errors++; $display("FAIL  probe register path"); end
      else $display("PASS  probe_encdec_tower register path (round 1)");
    end
    if (errors) $display("ROUND_TB FAIL (%0d)", errors); else $display("ROUND_TB PASS");
    $finish;
  end
endmodule
