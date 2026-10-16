# PH1 golden model + vectors. `make ph1` = everything Task 2-4 needs, from scratch.
PY      ?= python3
CAVP    ?= cavp/XTSGenAES128_hex.rsp cavp/XTSGenAES128_seq.rsp
SIM     ?= icarus          # icarus | xcelium

.PHONY: ph1 golden cavp vectors check_vectors vec_load clean
ph1: golden cavp vectors check_vectors vec_load

golden:
	cd golden && $(PY) golden_xts.py && $(PY) xcheck_openssl.py && $(PY) golden_kw.py && $(PY) xcheck_kw_openssl.py

cavp:
	cd golden && $(PY) cavp_xts.py $(addprefix ../,$(CAVP)) --log ../logs/cavp_xts.log

vectors:
	cd golden && $(PY) gen_vectors.py ../vectors

check_vectors: vectors
	cd golden && $(PY) check_vectors.py ../vectors

vec_load: vectors
ifeq ($(SIM),xcelium)
	cd tb && xrun -sv +incdir+../vectors tb_vec_load.sv +VEC=../vectors -l ../logs/vec_load.log
else
	cd tb && iverilog -g2012 -I ../vectors -o vl tb_vec_load.sv && vvp -n vl +VEC=../vectors | tee ../logs/vec_load.log
endif

clean:
	rm -rf vectors tb/vl golden/__pycache__
