# Task 6 fmax probe. Laptop: make gen sim.  cadence47: make sim SIM=xcelium; make fmax
SIM ?= icarus
RTL  = rtl/aes_sbox_pkg.sv rtl/aes_round_stage.sv rtl/aes_round_probe.sv
.PHONY: gen sim fmax report clean
gen:
	python3 gen/gen_sbox.py && python3 gen/gen_round_vectors.py
sim:
ifeq ($(SIM),xcelium)
	cd tb && xrun -sv $(addprefix ../,$(RTL)) tb_round.sv -top tb_round -l ../logs/round_xrun.log
else
	mkdir -p logs && cd tb && iverilog -g2012 -o rt $(addprefix ../,$(RTL)) tb_round.sv && vvp -n rt | tee ../logs/round_icarus.log
endif
fmax:
	./syn/run_fmax.sh
report:
	python3 syn/parse_fmax.py out
clean:
	rm -rf out logs tb/rt xcelium.d tb/xcelium.d
