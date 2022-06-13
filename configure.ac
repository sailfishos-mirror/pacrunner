AC_PREREQ([2.69])
AC_INIT([pacrunner], [0.18])

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AC_CONFIG_HEADERS(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${libdir}" = "${exec_prefix}/lib"); then
	libdir="${prefix}/lib"
fi

plugindir="${libdir}/pacrunner/plugins"

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG([C])

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL

LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(unit, AS_HELP_STRING([--enable-unit],
			[enable compiling unit test binaries]))
if (test "${enable_unit}" = "yes"); then
	AC_CHECK_LIB([cunit], CU_initialize_registry, dummy=yes,
		AC_MSG_ERROR([CUnit is required to get the unit tests]))
	CUNIT_CFLAGS=""
	CUNIT_LIBS="-lcunit"
	AC_SUBST(CUNIT_CFLAGS)
	AC_SUBST(CUNIT_LIBS)
fi
AM_CONDITIONAL(UNIT, test "${enable_unit}" = "yes")

AC_ARG_ENABLE(pie, AS_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

AC_ARG_ENABLE(duktape, AS_HELP_STRING([--enable-duktape],
		[enable Duktape Javascript plugin support]))
AM_CONDITIONAL(DUKTAPE, test "${enable_duktape}" = "yes")

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.16 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.2, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.2 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_ARG_WITH(dbusconfdir, AS_HELP_STRING([--with-dbusconfdir=PATH],
	[path to D-Bus config directory]), [path_dbusconf=${withval}],
		[path_dbusconf="`$PKG_CONFIG --variable=sysconfdir dbus-1`"])
if (test -z "${path_dbusconf}"); then
	DBUS_CONFDIR="${sysconfdir}/dbus-1/system.d"
else
	DBUS_CONFDIR="${path_dbusconf}/dbus-1/system.d"
fi
AC_SUBST(DBUS_CONFDIR)

AC_ARG_WITH(dbusdatadir, AS_HELP_STRING([--with-dbusdatadir=PATH],
	[path to D-Bus data directory]), [path_dbusdata=${withval}],
		[path_dbusdata="`$PKG_CONFIG --variable=datadir dbus-1`"])
if (test -z "${path_dbusdata}"); then
	DBUS_DATADIR="${datadir}/dbus-1/system-services"
else
	DBUS_DATADIR="${path_dbusdata}/dbus-1/system-services"
fi
AC_SUBST(DBUS_DATADIR)

AC_CHECK_LIB(pthread, pthread_create,
	[PTHREAD_LIBS="-lpthread"],
	[AC_MSG_ERROR([Pthread support is missing])])
AC_SUBST(PTHREAD_LIBS)

AC_ARG_ENABLE(curl, AS_HELP_STRING([--enable-curl],
		[enable CURL plugin support]), [enable_curl=${enableval}])
if (test "${enable_curl}" = "yes"); then
	PKG_CHECK_MODULES(CURL, libcurl >= 7.16, dummy=yes,
				AC_MSG_ERROR(CURL >= 7.16 is required))
	AC_SUBST(CURL_CFLAGS)
	AC_SUBST(CURL_LIBS)
fi
AM_CONDITIONAL(CURL, test "${enable_curl}" = "yes")

AC_ARG_ENABLE(test, AS_HELP_STRING([--enable-test],
		[enable test/example scripts]), [enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(libproxy, AS_HELP_STRING([--enable-libproxy],
	[enable libproxy compatible library]), [enable_libproxy=${enableval}])
AM_CONDITIONAL(LIBPROXY, test "${enable_libproxy}" = "yes")

AC_ARG_ENABLE(datafiles, AS_HELP_STRING([--disable-datafiles],
			[don't install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

AC_CONFIG_FILES(Makefile src/org.pacrunner.service libproxy/libproxy-1.0.pc)

AC_OUTPUT
