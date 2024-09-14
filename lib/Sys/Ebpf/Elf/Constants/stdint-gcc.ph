require '_h2ph_pre.ph';

no warnings qw(redefine misc);

unless(defined(&_GCC_STDINT_H)) {
    eval 'sub _GCC_STDINT_H () {1;}' unless defined(&_GCC_STDINT_H);
    if(defined(&__INT8_TYPE__)) {
    }
    if(defined(&__INT16_TYPE__)) {
    }
    if(defined(&__INT32_TYPE__)) {
    }
    if(defined(&__INT64_TYPE__)) {
    }
    if(defined(&__UINT8_TYPE__)) {
    }
    if(defined(&__UINT16_TYPE__)) {
    }
    if(defined(&__UINT32_TYPE__)) {
    }
    if(defined(&__UINT64_TYPE__)) {
    }
    if(defined(&__INTPTR_TYPE__)) {
    }
    if(defined(&__UINTPTR_TYPE__)) {
    }
    if((!defined (&__cplusplus) || (defined(&__cplusplus) ? &__cplusplus : undef) >= 201103 || defined (&__STDC_LIMIT_MACROS))) {
	if(defined(&__INT8_MAX__)) {
	    undef(&INT8_MAX) if defined(&INT8_MAX);
	    eval 'sub INT8_MAX () { &__INT8_MAX__;}' unless defined(&INT8_MAX);
	    undef(&INT8_MIN) if defined(&INT8_MIN);
	    eval 'sub INT8_MIN () {(- &INT8_MAX - 1);}' unless defined(&INT8_MIN);
	}
	if(defined(&__UINT8_MAX__)) {
	    undef(&UINT8_MAX) if defined(&UINT8_MAX);
	    eval 'sub UINT8_MAX () { &__UINT8_MAX__;}' unless defined(&UINT8_MAX);
	}
	if(defined(&__INT16_MAX__)) {
	    undef(&INT16_MAX) if defined(&INT16_MAX);
	    eval 'sub INT16_MAX () { &__INT16_MAX__;}' unless defined(&INT16_MAX);
	    undef(&INT16_MIN) if defined(&INT16_MIN);
	    eval 'sub INT16_MIN () {(- &INT16_MAX - 1);}' unless defined(&INT16_MIN);
	}
	if(defined(&__UINT16_MAX__)) {
	    undef(&UINT16_MAX) if defined(&UINT16_MAX);
	    eval 'sub UINT16_MAX () { &__UINT16_MAX__;}' unless defined(&UINT16_MAX);
	}
	if(defined(&__INT32_MAX__)) {
	    undef(&INT32_MAX) if defined(&INT32_MAX);
	    eval 'sub INT32_MAX () { &__INT32_MAX__;}' unless defined(&INT32_MAX);
	    undef(&INT32_MIN) if defined(&INT32_MIN);
	    eval 'sub INT32_MIN () {(- &INT32_MAX - 1);}' unless defined(&INT32_MIN);
	}
	if(defined(&__UINT32_MAX__)) {
	    undef(&UINT32_MAX) if defined(&UINT32_MAX);
	    eval 'sub UINT32_MAX () { &__UINT32_MAX__;}' unless defined(&UINT32_MAX);
	}
	if(defined(&__INT64_MAX__)) {
	    undef(&INT64_MAX) if defined(&INT64_MAX);
	    eval 'sub INT64_MAX () { &__INT64_MAX__;}' unless defined(&INT64_MAX);
	    undef(&INT64_MIN) if defined(&INT64_MIN);
	    eval 'sub INT64_MIN () {(- &INT64_MAX - 1);}' unless defined(&INT64_MIN);
	}
	if(defined(&__UINT64_MAX__)) {
	    undef(&UINT64_MAX) if defined(&UINT64_MAX);
	    eval 'sub UINT64_MAX () { &__UINT64_MAX__;}' unless defined(&UINT64_MAX);
	}
	undef(&INT_LEAST8_MAX) if defined(&INT_LEAST8_MAX);
	eval 'sub INT_LEAST8_MAX () { &__INT_LEAST8_MAX__;}' unless defined(&INT_LEAST8_MAX);
	undef(&INT_LEAST8_MIN) if defined(&INT_LEAST8_MIN);
	eval 'sub INT_LEAST8_MIN () {(- &INT_LEAST8_MAX - 1);}' unless defined(&INT_LEAST8_MIN);
	undef(&UINT_LEAST8_MAX) if defined(&UINT_LEAST8_MAX);
	eval 'sub UINT_LEAST8_MAX () { &__UINT_LEAST8_MAX__;}' unless defined(&UINT_LEAST8_MAX);
	undef(&INT_LEAST16_MAX) if defined(&INT_LEAST16_MAX);
	eval 'sub INT_LEAST16_MAX () { &__INT_LEAST16_MAX__;}' unless defined(&INT_LEAST16_MAX);
	undef(&INT_LEAST16_MIN) if defined(&INT_LEAST16_MIN);
	eval 'sub INT_LEAST16_MIN () {(- &INT_LEAST16_MAX - 1);}' unless defined(&INT_LEAST16_MIN);
	undef(&UINT_LEAST16_MAX) if defined(&UINT_LEAST16_MAX);
	eval 'sub UINT_LEAST16_MAX () { &__UINT_LEAST16_MAX__;}' unless defined(&UINT_LEAST16_MAX);
	undef(&INT_LEAST32_MAX) if defined(&INT_LEAST32_MAX);
	eval 'sub INT_LEAST32_MAX () { &__INT_LEAST32_MAX__;}' unless defined(&INT_LEAST32_MAX);
	undef(&INT_LEAST32_MIN) if defined(&INT_LEAST32_MIN);
	eval 'sub INT_LEAST32_MIN () {(- &INT_LEAST32_MAX - 1);}' unless defined(&INT_LEAST32_MIN);
	undef(&UINT_LEAST32_MAX) if defined(&UINT_LEAST32_MAX);
	eval 'sub UINT_LEAST32_MAX () { &__UINT_LEAST32_MAX__;}' unless defined(&UINT_LEAST32_MAX);
	undef(&INT_LEAST64_MAX) if defined(&INT_LEAST64_MAX);
	eval 'sub INT_LEAST64_MAX () { &__INT_LEAST64_MAX__;}' unless defined(&INT_LEAST64_MAX);
	undef(&INT_LEAST64_MIN) if defined(&INT_LEAST64_MIN);
	eval 'sub INT_LEAST64_MIN () {(- &INT_LEAST64_MAX - 1);}' unless defined(&INT_LEAST64_MIN);
	undef(&UINT_LEAST64_MAX) if defined(&UINT_LEAST64_MAX);
	eval 'sub UINT_LEAST64_MAX () { &__UINT_LEAST64_MAX__;}' unless defined(&UINT_LEAST64_MAX);
	undef(&INT_FAST8_MAX) if defined(&INT_FAST8_MAX);
	eval 'sub INT_FAST8_MAX () { &__INT_FAST8_MAX__;}' unless defined(&INT_FAST8_MAX);
	undef(&INT_FAST8_MIN) if defined(&INT_FAST8_MIN);
	eval 'sub INT_FAST8_MIN () {(- &INT_FAST8_MAX - 1);}' unless defined(&INT_FAST8_MIN);
	undef(&UINT_FAST8_MAX) if defined(&UINT_FAST8_MAX);
	eval 'sub UINT_FAST8_MAX () { &__UINT_FAST8_MAX__;}' unless defined(&UINT_FAST8_MAX);
	undef(&INT_FAST16_MAX) if defined(&INT_FAST16_MAX);
	eval 'sub INT_FAST16_MAX () { &__INT_FAST16_MAX__;}' unless defined(&INT_FAST16_MAX);
	undef(&INT_FAST16_MIN) if defined(&INT_FAST16_MIN);
	eval 'sub INT_FAST16_MIN () {(- &INT_FAST16_MAX - 1);}' unless defined(&INT_FAST16_MIN);
	undef(&UINT_FAST16_MAX) if defined(&UINT_FAST16_MAX);
	eval 'sub UINT_FAST16_MAX () { &__UINT_FAST16_MAX__;}' unless defined(&UINT_FAST16_MAX);
	undef(&INT_FAST32_MAX) if defined(&INT_FAST32_MAX);
	eval 'sub INT_FAST32_MAX () { &__INT_FAST32_MAX__;}' unless defined(&INT_FAST32_MAX);
	undef(&INT_FAST32_MIN) if defined(&INT_FAST32_MIN);
	eval 'sub INT_FAST32_MIN () {(- &INT_FAST32_MAX - 1);}' unless defined(&INT_FAST32_MIN);
	undef(&UINT_FAST32_MAX) if defined(&UINT_FAST32_MAX);
	eval 'sub UINT_FAST32_MAX () { &__UINT_FAST32_MAX__;}' unless defined(&UINT_FAST32_MAX);
	undef(&INT_FAST64_MAX) if defined(&INT_FAST64_MAX);
	eval 'sub INT_FAST64_MAX () { &__INT_FAST64_MAX__;}' unless defined(&INT_FAST64_MAX);
	undef(&INT_FAST64_MIN) if defined(&INT_FAST64_MIN);
	eval 'sub INT_FAST64_MIN () {(- &INT_FAST64_MAX - 1);}' unless defined(&INT_FAST64_MIN);
	undef(&UINT_FAST64_MAX) if defined(&UINT_FAST64_MAX);
	eval 'sub UINT_FAST64_MAX () { &__UINT_FAST64_MAX__;}' unless defined(&UINT_FAST64_MAX);
	if(defined(&__INTPTR_MAX__)) {
	    undef(&INTPTR_MAX) if defined(&INTPTR_MAX);
	    eval 'sub INTPTR_MAX () { &__INTPTR_MAX__;}' unless defined(&INTPTR_MAX);
	    undef(&INTPTR_MIN) if defined(&INTPTR_MIN);
	    eval 'sub INTPTR_MIN () {(- &INTPTR_MAX - 1);}' unless defined(&INTPTR_MIN);
	}
	if(defined(&__UINTPTR_MAX__)) {
	    undef(&UINTPTR_MAX) if defined(&UINTPTR_MAX);
	    eval 'sub UINTPTR_MAX () { &__UINTPTR_MAX__;}' unless defined(&UINTPTR_MAX);
	}
	undef(&INTMAX_MAX) if defined(&INTMAX_MAX);
	eval 'sub INTMAX_MAX () { &__INTMAX_MAX__;}' unless defined(&INTMAX_MAX);
	undef(&INTMAX_MIN) if defined(&INTMAX_MIN);
	eval 'sub INTMAX_MIN () {(- &INTMAX_MAX - 1);}' unless defined(&INTMAX_MIN);
	undef(&UINTMAX_MAX) if defined(&UINTMAX_MAX);
	eval 'sub UINTMAX_MAX () { &__UINTMAX_MAX__;}' unless defined(&UINTMAX_MAX);
	undef(&PTRDIFF_MAX) if defined(&PTRDIFF_MAX);
	eval 'sub PTRDIFF_MAX () { &__PTRDIFF_MAX__;}' unless defined(&PTRDIFF_MAX);
	undef(&PTRDIFF_MIN) if defined(&PTRDIFF_MIN);
	eval 'sub PTRDIFF_MIN () {(- &PTRDIFF_MAX - 1);}' unless defined(&PTRDIFF_MIN);
	undef(&SIG_ATOMIC_MAX) if defined(&SIG_ATOMIC_MAX);
	eval 'sub SIG_ATOMIC_MAX () { &__SIG_ATOMIC_MAX__;}' unless defined(&SIG_ATOMIC_MAX);
	undef(&SIG_ATOMIC_MIN) if defined(&SIG_ATOMIC_MIN);
	eval 'sub SIG_ATOMIC_MIN () { &__SIG_ATOMIC_MIN__;}' unless defined(&SIG_ATOMIC_MIN);
	undef(&SIZE_MAX) if defined(&SIZE_MAX);
	eval 'sub SIZE_MAX () { &__SIZE_MAX__;}' unless defined(&SIZE_MAX);
	undef(&WCHAR_MAX) if defined(&WCHAR_MAX);
	eval 'sub WCHAR_MAX () { &__WCHAR_MAX__;}' unless defined(&WCHAR_MAX);
	undef(&WCHAR_MIN) if defined(&WCHAR_MIN);
	eval 'sub WCHAR_MIN () { &__WCHAR_MIN__;}' unless defined(&WCHAR_MIN);
	undef(&WINT_MAX) if defined(&WINT_MAX);
	eval 'sub WINT_MAX () { &__WINT_MAX__;}' unless defined(&WINT_MAX);
	undef(&WINT_MIN) if defined(&WINT_MIN);
	eval 'sub WINT_MIN () { &__WINT_MIN__;}' unless defined(&WINT_MIN);
    }
    if((!defined (&__cplusplus) || (defined(&__cplusplus) ? &__cplusplus : undef) >= 201103 || defined (&__STDC_CONSTANT_MACROS))) {
	undef(&INT8_C) if defined(&INT8_C);
	eval 'sub INT8_C {
	    my($c) = @_;
    	    eval q( &__INT8_C($c));
	}' unless defined(&INT8_C);
	undef(&INT16_C) if defined(&INT16_C);
	eval 'sub INT16_C {
	    my($c) = @_;
    	    eval q( &__INT16_C($c));
	}' unless defined(&INT16_C);
	undef(&INT32_C) if defined(&INT32_C);
	eval 'sub INT32_C {
	    my($c) = @_;
    	    eval q( &__INT32_C($c));
	}' unless defined(&INT32_C);
	undef(&INT64_C) if defined(&INT64_C);
	eval 'sub INT64_C {
	    my($c) = @_;
    	    eval q( &__INT64_C($c));
	}' unless defined(&INT64_C);
	undef(&UINT8_C) if defined(&UINT8_C);
	eval 'sub UINT8_C {
	    my($c) = @_;
    	    eval q( &__UINT8_C($c));
	}' unless defined(&UINT8_C);
	undef(&UINT16_C) if defined(&UINT16_C);
	eval 'sub UINT16_C {
	    my($c) = @_;
    	    eval q( &__UINT16_C($c));
	}' unless defined(&UINT16_C);
	undef(&UINT32_C) if defined(&UINT32_C);
	eval 'sub UINT32_C {
	    my($c) = @_;
    	    eval q( &__UINT32_C($c));
	}' unless defined(&UINT32_C);
	undef(&UINT64_C) if defined(&UINT64_C);
	eval 'sub UINT64_C {
	    my($c) = @_;
    	    eval q( &__UINT64_C($c));
	}' unless defined(&UINT64_C);
	undef(&INTMAX_C) if defined(&INTMAX_C);
	eval 'sub INTMAX_C {
	    my($c) = @_;
    	    eval q( &__INTMAX_C($c));
	}' unless defined(&INTMAX_C);
	undef(&UINTMAX_C) if defined(&UINTMAX_C);
	eval 'sub UINTMAX_C {
	    my($c) = @_;
    	    eval q( &__UINTMAX_C($c));
	}' unless defined(&UINTMAX_C);
    }
    if((defined (&__STDC_WANT_IEC_60559_BFP_EXT__) || (defined (&__STDC_VERSION__)  && (defined(&__STDC_VERSION__) ? &__STDC_VERSION__ : undef) > 201710))) {
	if(defined(&__INT8_TYPE__)) {
	    undef(&INT8_WIDTH) if defined(&INT8_WIDTH);
	    eval 'sub INT8_WIDTH () {8;}' unless defined(&INT8_WIDTH);
	}
	if(defined(&__UINT8_TYPE__)) {
	    undef(&UINT8_WIDTH) if defined(&UINT8_WIDTH);
	    eval 'sub UINT8_WIDTH () {8;}' unless defined(&UINT8_WIDTH);
	}
	if(defined(&__INT16_TYPE__)) {
	    undef(&INT16_WIDTH) if defined(&INT16_WIDTH);
	    eval 'sub INT16_WIDTH () {16;}' unless defined(&INT16_WIDTH);
	}
	if(defined(&__UINT16_TYPE__)) {
	    undef(&UINT16_WIDTH) if defined(&UINT16_WIDTH);
	    eval 'sub UINT16_WIDTH () {16;}' unless defined(&UINT16_WIDTH);
	}
	if(defined(&__INT32_TYPE__)) {
	    undef(&INT32_WIDTH) if defined(&INT32_WIDTH);
	    eval 'sub INT32_WIDTH () {32;}' unless defined(&INT32_WIDTH);
	}
	if(defined(&__UINT32_TYPE__)) {
	    undef(&UINT32_WIDTH) if defined(&UINT32_WIDTH);
	    eval 'sub UINT32_WIDTH () {32;}' unless defined(&UINT32_WIDTH);
	}
	if(defined(&__INT64_TYPE__)) {
	    undef(&INT64_WIDTH) if defined(&INT64_WIDTH);
	    eval 'sub INT64_WIDTH () {64;}' unless defined(&INT64_WIDTH);
	}
	if(defined(&__UINT64_TYPE__)) {
	    undef(&UINT64_WIDTH) if defined(&UINT64_WIDTH);
	    eval 'sub UINT64_WIDTH () {64;}' unless defined(&UINT64_WIDTH);
	}
	undef(&INT_LEAST8_WIDTH) if defined(&INT_LEAST8_WIDTH);
	eval 'sub INT_LEAST8_WIDTH () { &__INT_LEAST8_WIDTH__;}' unless defined(&INT_LEAST8_WIDTH);
	undef(&UINT_LEAST8_WIDTH) if defined(&UINT_LEAST8_WIDTH);
	eval 'sub UINT_LEAST8_WIDTH () { &__INT_LEAST8_WIDTH__;}' unless defined(&UINT_LEAST8_WIDTH);
	undef(&INT_LEAST16_WIDTH) if defined(&INT_LEAST16_WIDTH);
	eval 'sub INT_LEAST16_WIDTH () { &__INT_LEAST16_WIDTH__;}' unless defined(&INT_LEAST16_WIDTH);
	undef(&UINT_LEAST16_WIDTH) if defined(&UINT_LEAST16_WIDTH);
	eval 'sub UINT_LEAST16_WIDTH () { &__INT_LEAST16_WIDTH__;}' unless defined(&UINT_LEAST16_WIDTH);
	undef(&INT_LEAST32_WIDTH) if defined(&INT_LEAST32_WIDTH);
	eval 'sub INT_LEAST32_WIDTH () { &__INT_LEAST32_WIDTH__;}' unless defined(&INT_LEAST32_WIDTH);
	undef(&UINT_LEAST32_WIDTH) if defined(&UINT_LEAST32_WIDTH);
	eval 'sub UINT_LEAST32_WIDTH () { &__INT_LEAST32_WIDTH__;}' unless defined(&UINT_LEAST32_WIDTH);
	undef(&INT_LEAST64_WIDTH) if defined(&INT_LEAST64_WIDTH);
	eval 'sub INT_LEAST64_WIDTH () { &__INT_LEAST64_WIDTH__;}' unless defined(&INT_LEAST64_WIDTH);
	undef(&UINT_LEAST64_WIDTH) if defined(&UINT_LEAST64_WIDTH);
	eval 'sub UINT_LEAST64_WIDTH () { &__INT_LEAST64_WIDTH__;}' unless defined(&UINT_LEAST64_WIDTH);
	undef(&INT_FAST8_WIDTH) if defined(&INT_FAST8_WIDTH);
	eval 'sub INT_FAST8_WIDTH () { &__INT_FAST8_WIDTH__;}' unless defined(&INT_FAST8_WIDTH);
	undef(&UINT_FAST8_WIDTH) if defined(&UINT_FAST8_WIDTH);
	eval 'sub UINT_FAST8_WIDTH () { &__INT_FAST8_WIDTH__;}' unless defined(&UINT_FAST8_WIDTH);
	undef(&INT_FAST16_WIDTH) if defined(&INT_FAST16_WIDTH);
	eval 'sub INT_FAST16_WIDTH () { &__INT_FAST16_WIDTH__;}' unless defined(&INT_FAST16_WIDTH);
	undef(&UINT_FAST16_WIDTH) if defined(&UINT_FAST16_WIDTH);
	eval 'sub UINT_FAST16_WIDTH () { &__INT_FAST16_WIDTH__;}' unless defined(&UINT_FAST16_WIDTH);
	undef(&INT_FAST32_WIDTH) if defined(&INT_FAST32_WIDTH);
	eval 'sub INT_FAST32_WIDTH () { &__INT_FAST32_WIDTH__;}' unless defined(&INT_FAST32_WIDTH);
	undef(&UINT_FAST32_WIDTH) if defined(&UINT_FAST32_WIDTH);
	eval 'sub UINT_FAST32_WIDTH () { &__INT_FAST32_WIDTH__;}' unless defined(&UINT_FAST32_WIDTH);
	undef(&INT_FAST64_WIDTH) if defined(&INT_FAST64_WIDTH);
	eval 'sub INT_FAST64_WIDTH () { &__INT_FAST64_WIDTH__;}' unless defined(&INT_FAST64_WIDTH);
	undef(&UINT_FAST64_WIDTH) if defined(&UINT_FAST64_WIDTH);
	eval 'sub UINT_FAST64_WIDTH () { &__INT_FAST64_WIDTH__;}' unless defined(&UINT_FAST64_WIDTH);
	if(defined(&__INTPTR_TYPE__)) {
	    undef(&INTPTR_WIDTH) if defined(&INTPTR_WIDTH);
	    eval 'sub INTPTR_WIDTH () { &__INTPTR_WIDTH__;}' unless defined(&INTPTR_WIDTH);
	}
	if(defined(&__UINTPTR_TYPE__)) {
	    undef(&UINTPTR_WIDTH) if defined(&UINTPTR_WIDTH);
	    eval 'sub UINTPTR_WIDTH () { &__INTPTR_WIDTH__;}' unless defined(&UINTPTR_WIDTH);
	}
	undef(&INTMAX_WIDTH) if defined(&INTMAX_WIDTH);
	eval 'sub INTMAX_WIDTH () { &__INTMAX_WIDTH__;}' unless defined(&INTMAX_WIDTH);
	undef(&UINTMAX_WIDTH) if defined(&UINTMAX_WIDTH);
	eval 'sub UINTMAX_WIDTH () { &__INTMAX_WIDTH__;}' unless defined(&UINTMAX_WIDTH);
	undef(&PTRDIFF_WIDTH) if defined(&PTRDIFF_WIDTH);
	eval 'sub PTRDIFF_WIDTH () { &__PTRDIFF_WIDTH__;}' unless defined(&PTRDIFF_WIDTH);
	undef(&SIG_ATOMIC_WIDTH) if defined(&SIG_ATOMIC_WIDTH);
	eval 'sub SIG_ATOMIC_WIDTH () { &__SIG_ATOMIC_WIDTH__;}' unless defined(&SIG_ATOMIC_WIDTH);
	undef(&SIZE_WIDTH) if defined(&SIZE_WIDTH);
	eval 'sub SIZE_WIDTH () { &__SIZE_WIDTH__;}' unless defined(&SIZE_WIDTH);
	undef(&WCHAR_WIDTH) if defined(&WCHAR_WIDTH);
	eval 'sub WCHAR_WIDTH () { &__WCHAR_WIDTH__;}' unless defined(&WCHAR_WIDTH);
	undef(&WINT_WIDTH) if defined(&WINT_WIDTH);
	eval 'sub WINT_WIDTH () { &__WINT_WIDTH__;}' unless defined(&WINT_WIDTH);
    }
}
1;
