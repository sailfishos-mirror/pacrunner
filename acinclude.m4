AC_DEFUN([AC_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], ac_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_pie=yes
		else
			ac_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([COMPILER_FLAGS], [
	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
	fi
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		CFLAGS+=" -Werror -Wextra"
		CFLAGS+=" -Wno-unused-parameter"
		CFLAGS+=" -Wno-missing-field-initializers"
		CFLAGS+=" -Wdeclaration-after-statement"
		CFLAGS+=" -Wmissing-declarations"
		CFLAGS+=" -Wredundant-decls"
		CFLAGS+=" -Wcast-align"
		CFLAGS+=" -DG_DISABLE_DEPRECATED"
	fi
])

AC_DEFUN([AX_CHECK_COMPILE_FLAG], [
	AS_VAR_PUSHDEF([CACHEVAR],[ax_cv_check_[]_AC_LANG_ABBREV[]flags_$4_$1])
	AC_CACHE_CHECK([whether _AC_LANG compiler accepts $1], CACHEVAR, [
		ax_check_save_flags=$[]_AC_LANG_PREFIX[]FLAGS
		_AC_LANG_PREFIX[]FLAGS="$[]_AC_LANG_PREFIX[]FLAGS $4 $1"
		AC_COMPILE_IFELSE([m4_default([$5],[AC_LANG_PROGRAM()])],
						[AS_VAR_SET(CACHEVAR,[yes])],
						[AS_VAR_SET(CACHEVAR,[no])])
		_AC_LANG_PREFIX[]FLAGS=$ax_check_save_flags])
	AS_VAR_IF(CACHEVAR,yes, [m4_default([$2], :)], [m4_default([$3], :)])
	AS_VAR_POPDEF([CACHEVAR])
])
