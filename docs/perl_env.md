# developer docs

## build and install
```shell
perl Makefile.PL
make
make test
make install
```

## running unittest
```shell
sudo prove -v -l t/*.t
```

## devlop setting
```shell
pip install pre-commit
pre-commit install
```

## Running Linting
```shell
pre-commit run -a
```

## package update
```shell
sudo PERL5LIB=$PERL5LIB $(which minil) test
```

## bpf printk
```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```