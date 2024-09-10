# perl-ebpf
The goal of this project is to enable the attachment of eBPF programs from Perl, create eBPF maps, and perform operations on those eBPF maps.

## for develop
```shell
perl Makefile.PL
make
make test
make install

# dest upload
make dest
```

### running unittest
```shell
prove -v -l t/*.t
```

