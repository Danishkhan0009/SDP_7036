// aes_round_stage.sv - one AES-128 pipeline stage (Spec Section 1, DD4/DD5), combinational.
// Byte convention (Spec D12): byte k of a 128-bit word is bits [8k+7:8k];
// AES state byte k = row (k % 4), column (k / 4), same as FIPS-197 byte order.
//
// MODE       0 = encrypt only, 1 = encrypt + decrypt (dir selects)
// SBOX_STYLE 0 = LUT (case table), 1 = composite field (dec shares the inverter)
// IS_LAST    1 = final round (no MixColumns / InvMixColumns)
//
// Encrypt round r (1..10):  rk_out = KeyExp(rk_in = rk[r-1], rcon)
//                           s_out  = MixCol(Sub(Shift(s_in))) ^ rk_out
// Decrypt round r (9..0):   rk_out = InvKeyExp(rk_in = rk[r+1], rcon)
//                           s_out  = InvMix(InvSub(InvShift(s_in)) ^ rk_out)
// (ShiftRows and SubBytes commute, so both directions share one shift-then-sub order.)
module aes_round_stage #(
  parameter int MODE       = 1,
  parameter int SBOX_STYLE = 0,
  parameter bit IS_LAST    = 0
) (
  input  logic         dir,      // 0 encrypt, 1 decrypt (ignored when MODE = 0)
  input  logic [127:0] s_in,
  input  logic [127:0] rk_in,
  input  logic [7:0]   rcon,
  output logic [127:0] s_out,
  output logic [127:0] rk_out
);
  import aes_sbox_pkg::*;

  function automatic logic [7:0] xt(input logic [7:0] b);   // multiply by x
    return {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
  endfunction

  function automatic logic [7:0] sb_fwd(input logic [7:0] x);
    return (SBOX_STYLE == 0) ? sbox_lut(x) : sbox_tower(x);
  endfunction

  function automatic logic [7:0] sb_ed(input logic [7:0] x, input logic d);
    if (SBOX_STYLE == 0) return d ? isbox_lut(x) : sbox_lut(x);
    else                 return sbox_tower_ed(x, d);
  endfunction

  logic dec;
  assign dec = (MODE == 1) ? dir : 1'b0;

  // ---------------- key schedule step (forward S-box in both directions)
  function automatic logic [127:0] key_step(input logic [127:0] rk, input logic [7:0] rc, input logic d);
    logic [31:0] w0, w1, w2, w3, n0, n1, n2, n3, t, k3;
    {w3, w2, w1, w0} = rk;
    if (!d) begin                       // forward: rk[r] from rk[r-1]
      t  = {sb_fwd(w3[7:0]), sb_fwd(w3[31:24]), sb_fwd(w3[23:16]), sb_fwd(w3[15:8]) ^ rc};
      n0 = w0 ^ t; n1 = w1 ^ n0; n2 = w2 ^ n1; n3 = w3 ^ n2;
    end else begin                      // inverse: rk[r] from rk[r+1]
      k3 = w3 ^ w2;
      t  = {sb_fwd(k3[7:0]), sb_fwd(k3[31:24]), sb_fwd(k3[23:16]), sb_fwd(k3[15:8]) ^ rc};
      n3 = k3; n2 = w2 ^ w1; n1 = w1 ^ w0; n0 = w0 ^ t;
    end
    return {n3, n2, n1, n0};
  endfunction

  // ---------------- data path
  function automatic logic [7:0] get(input logic [127:0] v, input int k);
    return v[8*k +: 8];
  endfunction

  function automatic logic [127:0] round_fn(input logic [127:0] s, input logic [127:0] rk, input logic d);
    logic [127:0] sh, sb, mc, ark, im, o;
    logic [7:0] a0, a1, a2, a3, x1, x2, x3, y1, y2, y3, z1, z2, z3, u1, u2, u3;
    // ShiftRows / InvShiftRows: out[r + 4c] = in[r + 4((c +/- r) mod 4)]
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++)
        sh[8*(r + 4*c) +: 8] = d ? get(s, r + 4*((c - r + 4) % 4)) : get(s, r + 4*((c + r) % 4));
    for (int k = 0; k < 16; k++)
      sb[8*k +: 8] = (MODE == 0) ? sb_fwd(get(sh, k)) : sb_ed(get(sh, k), d);
    for (int c = 0; c < 4; c++) begin   // MixColumns
      a0 = get(sb, 4*c); a1 = get(sb, 4*c+1); a2 = get(sb, 4*c+2); a3 = get(sb, 4*c+3);
      mc[8*(4*c)   +: 8] = xt(a0) ^ (xt(a1) ^ a1) ^ a2 ^ a3;
      mc[8*(4*c+1) +: 8] = a0 ^ xt(a1) ^ (xt(a2) ^ a2) ^ a3;
      mc[8*(4*c+2) +: 8] = a0 ^ a1 ^ xt(a2) ^ (xt(a3) ^ a3);
      mc[8*(4*c+3) +: 8] = (xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3);
    end
    ark = sb ^ rk;                      // decrypt: AddRoundKey before InvMixColumns
    for (int c = 0; c < 4; c++) begin   // InvMixColumns: 0e 0b 0d 09
      a0 = get(ark, 4*c); a1 = get(ark, 4*c+1); a2 = get(ark, 4*c+2); a3 = get(ark, 4*c+3);
      x1 = xt(a0); x2 = xt(x1); x3 = xt(x2);
      y1 = xt(a1); y2 = xt(y1); y3 = xt(y2);
      z1 = xt(a2); z2 = xt(z1); z3 = xt(z2);
      u1 = xt(a3); u2 = xt(u1); u3 = xt(u2);
      im[8*(4*c)   +: 8] = (x3^x2^x1) ^ (y3^y1^a1) ^ (z3^z2^a2) ^ (u3^a3);
      im[8*(4*c+1) +: 8] = (y3^y2^y1) ^ (z3^z1^a2) ^ (u3^u2^a3) ^ (x3^a0);
      im[8*(4*c+2) +: 8] = (z3^z2^z1) ^ (u3^u1^a3) ^ (x3^x2^a0) ^ (y3^a1);
      im[8*(4*c+3) +: 8] = (u3^u2^u1) ^ (x3^x1^a0) ^ (y3^y2^a1) ^ (z3^a2);
    end
    if (IS_LAST) o = ark;
    else if (d)  o = im;
    else         o = mc ^ rk;
    return o;
  endfunction

  assign rk_out = key_step(rk_in, rcon, dec);
  assign s_out  = round_fn(s_in, rk_out, dec);
endmodule
