AC_PREREQ(2.61)

AC_INIT(couriergrey.h)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(couriergrey,0.3.1)
AM_CONFIG_HEADER(config.h)
AC_LANG(C++)
AC_GNU_SOURCE

sinclude(ac-helpers/ac_define_dir.m4)

dnl Check for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_ICONV

AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION(0.16.1)
ALL_LINGUAS=""

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_SUBST([localedir], ['${datadir}/locale'])

dnl headers we need
AC_HEADER_STDC

dnl static builds
AC_MSG_CHECKING(if static builds enabled)
AC_ARG_ENABLE(all-static, AC_HELP_STRING([--enable-all-static], [Build static binaries]), all_static=yes, all_static=no)
if test "x-$all_static" = "x-yes" ; then
    LDFLAGS="$LDFLAGS -Wl,-static -static"
fi
AC_MSG_RESULT($all_static)

AC_MSG_CHECKING(if partial static builds enabled)
AC_ARG_ENABLE(partial-static, AC_HELP_STRING([--enable-partial-static], [Build partially static binaries]), partial_static=yes, partial_static=no)
if test "x-$partial_static" = "x-yes" ; then
    LDFLAGS="$LDFLAGS -Wl,-lc,-static -static"
fi
AC_MSG_RESULT($partial_static)

AC_DEFINE_DIR(LOCALSTATEDIR, localstatedir, [base where spool can be found])

dnl check for libpopt
AC_ARG_WITH(libpopt, AC_HELP_STRING([--with-libpopt=DIR],
	    [Where to find libpopt (required)]),
	    libpopt=$withval, libpopt=yes)
if test "$libpopt" != "no"; then
    if test "$libpopt" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$libpopt/lib -R$libpopt/lib"
	CPPFLAGS="${CPPFLAGS} -I$libpopt/include"
    fi
    AC_CHECK_HEADER(popt.h,
		    AC_CHECK_LIB(popt, poptStrerror,
				 [libpopt=yes LIBS="${LIBS} -lpopt"], libpopt=no),
				 libpopt=no)
fi
if test "$libpopt" != "yes"; then
    AC_MSG_ERROR([Couldn't find required libpopt installation])
fi

dnl check for glibmm-2.4
PKG_CHECK_MODULES(GLIBMM, glibmm-2.4 >= 2.12.0, hasglibmm=yes, hasglibmm=no)
if test $hasglibmm = "no" ; then
    AC_MSG_ERROR($GLIBMM_PKG_ERRORS)
fi
CPPFLAGS="$CPPFLAGS $GLIBMM_CFLAGS"
LIBS="$LIBS $GLIBMM_LIBS"

dnl check for gthread
PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.0.0, hasgthread=yes, hasgthread=no)
if test $hasgthread = "no" ; then
    AC_MSG_ERROR($GTHREAD_PKG_ERRORS)
fi
CPPFLAGS="$CPPFLAGS $GTHREAD_CFLAGS"
LIBS="$LIBS $GTHREAD_LIBS"

dnl check for libgdbm
AC_ARG_WITH(libgdbm, AC_HELP_STRING([--with-libgdbm=DIR],
	    [Where to find libgdbm (required)]),
	    libgdbm=$withval, libgdbm=yes)
if test "$libgdbm" != "no"; then
    if test "$libgdbm" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$libgdbm/lib -R$libgdbm/lib"
	CPPFLAGS="${CPPFLAGS} -I$libgdbm/include"
    fi
    AC_CHECK_HEADER(gdbm.h,
		    AC_CHECK_LIB(gdbm, gdbm_open,
				 [libgdbm=yes LIBS="${LIBS} -lgdbm"], libgdbm=no),
				 libgdbm=no)
fi
if test "$libgdbm" != "yes"; then
    AC_MSG_ERROR([Couldn't find required libgdbm installation])
fi

dnl define where the configuration file is located
AC_DEFINE_DIR(CONFIG_DIR,sysconfdir,[where the configuration file can be found])

AC_DEFINE_DIR(STATE_DIR,localstatedir,[where the socket is created in])

dnl Create the makefiles
AC_OUTPUT(Makefile intl/Makefile po/Makefile.in m4/Makefile man/Makefile )
