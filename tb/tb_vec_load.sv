// tb_vec_load.sv - Task 4.9 loader smoke test. Reads every vector file with $readmemh,
// checks record counts, first/last fields against vec_expect.svh, and the byte-order rule.
// Run (Icarus): iverilog -g2012 -I ../vectors -o vl tb_vec_load.sv && vvp vl +VEC=../vectors
// Run (Xcelium): xrun -sv +incdir+../vectors tb_vec_load.sv +VEC=../vectors
`timescale 1ns/1ps
`include "vec_layout.svh"
`include "vec_expect.svh"
module tb_vec_load;
  localparam int MAXR = 4096;
  reg [`XTS_W-1:0]     xd [0:MAXR-1];
  reg [`XTS_W-1:0]     xr [0:MAXR-1];
  reg [`TRACE_W-1:0]   tr [0:MAXR-1];
  reg [`KEYSLOT_W-1:0] ks [0:MAXR-1];
  reg [`KW_W-1:0]      kw [0:MAXR-1];
  string dir; int errors = 0;

  function automatic int count_xts(input string which);
    int n = 0;
    if (which == "d") while (n < MAXR && !$isunknown(xd[n])) n++;
    else              while (n < MAXR && !$isunknown(xr[n])) n++;
    return n;
  endfunction

  task automatic check(input string what, input logic ok);
    if (!ok) begin errors++; $display("FAIL  %s", what); end
    else $display("PASS  %s", what);
  endtask

  initial begin
    int n;
    if (!$value$plusargs("VEC=%s", dir)) dir = "../vectors";
    $readmemh({dir, "/xts_directed.hex"}, xd);
    $readmemh({dir, "/xts_random.hex"},   xr);
    $readmemh({dir, "/xts_trace.hex"},    tr);
    $readmemh({dir, "/keyslot.hex"},      ks);
    $readmemh({dir, "/kw_standby.hex"},   kw);

    check($sformatf("xts_directed count %0d", count_xts("d")), count_xts("d") == `N_XTS_DIRECTED);
    check($sformatf("xts_random   count %0d", count_xts("r")), count_xts("r") == `N_XTS_RANDOM);
    n = 0; while (n < MAXR && !$isunknown(tr[n])) n++;
    check($sformatf("xts_trace    count %0d", n), n == `N_XTS_TRACE);
    n = 0; while (n < MAXR && !$isunknown(ks[n])) n++;
    check($sformatf("keyslot      count %0d", n), n == `N_KEYSLOT);
    n = 0; while (n < MAXR && !$isunknown(kw[n])) n++;
    check($sformatf("kw_standby   count %0d", n), n == `N_KW_STANDBY);

    // field slicing: first and last records match what the generator packed
    check("directed[0]   CTRL/ADDR/K1/DOUT", xd[0][`XTS_CTRL] == `XTS_DIRECTED_FIRST_CTRL &&
          xd[0][`XTS_ADDR] == `XTS_DIRECTED_FIRST_ADDR && xd[0][`XTS_K1] == `XTS_DIRECTED_FIRST_K1 &&
          xd[0][`XTS_DOUT] == `XTS_DIRECTED_FIRST_DOUT);
    check("random[last]  CTRL/ADDR/DIN/DOUT", xr[`N_XTS_RANDOM-1][`XTS_CTRL] == `XTS_RANDOM_LAST_CTRL &&
          xr[`N_XTS_RANDOM-1][`XTS_ADDR] == `XTS_RANDOM_LAST_ADDR &&
          xr[`N_XTS_RANDOM-1][`XTS_DIN] == `XTS_RANDOM_LAST_DIN &&
          xr[`N_XTS_RANDOM-1][`XTS_DOUT] == `XTS_RANDOM_LAST_DOUT);
    check("keyslot[0]    RK10 (FIPS-197 key)", ks[0][`KEYSLOT_RK10] == `KEYSLOT_FIRST_RK10);
    check("kw[last]      OK=0 reject case", kw[`N_KW_STANDBY-1][`KW_OK] == 0 &&
          kw[`N_KW_STANDBY-1][`KW_BLOB] == `KW_STANDBY_LAST_BLOB);

    // byte-order rule: trace of directed record 0, block j, must equal DIN/DOUT[128j+127:128j]
    for (int j = 0; j < 4; j++) begin
      logic [511:0] din, dout;
      din = xd[0][`XTS_DIN]; dout = xd[0][`XTS_DOUT];
      check($sformatf("byte order: block %0d of line 0 = DIN[%0d:%0d], DOUT matches", j, 128*j+127, 128*j),
            tr[j][`TRACE_REC] == 0 && tr[j][`TRACE_J] == j &&
            tr[j][`TRACE_BIN]  == din[128*j +: 128] &&
            tr[j][`TRACE_BOUT] == dout[128*j +: 128]);
    end
    // trace internal XORs hold for every traced block
    n = 0;
    for (int i = 0; i < `N_XTS_TRACE; i++)
      if ((tr[i][`TRACE_PRE] !== (tr[i][`TRACE_BIN] ^ tr[i][`TRACE_T])) ||
          (tr[i][`TRACE_BOUT] !== (tr[i][`TRACE_AES] ^ tr[i][`TRACE_T]))) n++;
    check($sformatf("trace XOR consistency (%0d blocks)", `N_XTS_TRACE), n == 0);

    if (errors == 0) $display("VEC_LOAD PASS"); else $display("VEC_LOAD FAIL (%0d)", errors);
    $finish;
  end
endmodule
