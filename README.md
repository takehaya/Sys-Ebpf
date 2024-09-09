# perl-ebpf
The goal of this project is to enable the attachment of eBPF programs from Perl, create eBPF maps, and perform operations on those eBPF maps.

## for develop
```shell
perl Makefile.PL
make
make test
make install
```

### running unittest
```shell
prove -v -l t/*.t
```

### develop for iteration
```shell
make clean
perl Makefile.PL
make
# move to `c_bpf_loader.o`
mv c_bpf_loader.o lib/ebpf
# recomplie
make
make install
```