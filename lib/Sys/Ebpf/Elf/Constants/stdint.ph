require '_h2ph_pre.ph';

no warnings qw(redefine misc);

unless(defined(&_GCC_WRAP_STDINT_H)) {
    if((defined(&__STDC_HOSTED__) ? &__STDC_HOSTED__ : undef)) {
	if(defined (&__cplusplus)  && (defined(&__cplusplus) ? &__cplusplus : undef) >= 201103) {
	    undef(&__STDC_LIMIT_MACROS) if defined(&__STDC_LIMIT_MACROS);
	    eval 'sub __STDC_LIMIT_MACROS () {1;}' unless defined(&__STDC_LIMIT_MACROS);
	    undef(&__STDC_CONSTANT_MACROS) if defined(&__STDC_CONSTANT_MACROS);
	    eval 'sub __STDC_CONSTANT_MACROS () {1;}' unless defined(&__STDC_CONSTANT_MACROS);
	}
	eval {
	    my(@REM);
	    my(%INCD) = map { $INC{$_} => 1 } (grep { $_ eq "stdint.ph" } keys(%INC));
	    @REM = map { "$_/stdint.ph" } (grep { not exists($INCD{"$_/stdint.ph"}) and -f "$_/stdint.ph" } @INC);
	    require "$REM[0]" if @REM;
	};
	warn($@) if $@;
    } else {
	require 'stdint-gcc.ph';
    }
    eval 'sub _GCC_WRAP_STDINT_H () {1;}' unless defined(&_GCC_WRAP_STDINT_H);
}
1;
