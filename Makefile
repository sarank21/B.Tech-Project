eth := wlp2s0
objfile := data_collector

make read: a.out data.csv
	rm data.csv
	./a.out

data_reader: data_reader.c
	gcc data_reader.c -lbpf

load:
	tc qdisc add dev $(eth) clsact
	tc filter add dev $(eth) ingress bpf direct-action obj $(objfile) sec .text


data_collector: data_collector.c
	clang -O2 -emit-llvm -c data_collector.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o $@

data.csv:
	touch data.csv

clean:
	tc qdisc del dev $(eth) clsact
	rm -f $(objfile)
	rm -r /sys/fs/bpf/tc
	rm -r /sys/fs/bpf/ip
	rm -r /sys/fs/bpf/xdp