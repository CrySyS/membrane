 #********************IMPORTANT DRAKVUF LICENSE TERMS**********************#
 #                                                                         #
 # DRAKVUF Dynamic Malware Analysis System (C) 2014 Tamas K Lengyel.       #
 # Tamas K Lengyel is hereinafter referred to as the author.               #
 # This program is free software; you may redistribute and/or modify it    #
 # under the terms of the GNU General Public License as published by the   #
 # Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   #
 # CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   # 
 # right to use, modify, and redistribute this software under certain      # 
 # conditions.  If you wish to embed DRAKVUF technology into proprietary   #
 # software, alternative licenses can be aquired from the author.          #
 #                                                                         #
 # Note that the GPL places important restrictions on "derivative works",  #
 # yet it does not provide a detailed definition of that term.  To avoid   #
 # misunderstandings, we interpret that term as broadly as copyright law   #
 # allows.  For example, we consider an application to constitute a        #
 # derivative work for the purpose of this license if it does any of the   #
 # following with any software or content covered by this license          #
 # ("Covered Software"):                                                   #
 #                                                                         #
 # o Integrates source code from Covered Software.                         #
 #                                                                         #
 # o Reads or includes copyrighted data files.                             #
 #                                                                         #
 # o Is designed specifically to execute Covered Software and parse the    #
 # results (as opposed to typical shell or execution-menu apps, which will #
 # execute anything you tell them to).                                     #
 #                                                                         #
 # o Includes Covered Software in a proprietary executable installer.  The #
 # installers produced by InstallShield are an example of this.  Including #
 # DRAKVUF with other software in compressed or archival form does not     #
 # trigger this provision, provided appropriate open source decompression  #
 # or de-archiving software is widely available for no charge.  For the    #
 # purposes of this license, an installer is considered to include Covered #
 # Software even if it actually retrieves a copy of Covered Software from  #
 # another source during runtime (such as by downloading it from the       #
 # Internet).                                                              #
 #                                                                         #
 # o Links (statically or dynamically) to a library which does any of the  #
 # above.                                                                  #
 #                                                                         #
 # o Executes a helper program, module, or script to do any of the above.  #
 #                                                                         #
 # This list is not exclusive, but is meant to clarify our interpretation  #
 # of derived works with some common examples.  Other people may interpret #
 # the plain GPL differently, so we consider this a special exception to   #
 # the GPL that we apply to Covered Software.  Works which meet any of     #
 # these conditions must conform to all of the terms of this license,      #
 # particularly including the GPL Section 3 requirements of providing      #
 # source code and allowing free redistribution of the work as a whole.    #
 #                                                                         #
 # Any redistribution of Covered Software, including any derived works,    #
 # must obey and carry forward all of the terms of this license, including #
 # obeying all GPL rules and restrictions.  For example, source code of    #
 # the whole work must be provided and free redistribution must be         #
 # allowed.  All GPL references to "this License", are to be treated as    #
 # including the terms and conditions of this license text as well.        #
 #                                                                         #
 # Because this license imposes special exceptions to the GPL, Covered     #
 # Work may not be combined (even as part of a larger work) with plain GPL #
 # software.  The terms, conditions, and exceptions of this license must   #
 # be included as well.  This license is incompatible with some other open #
 # source licenses as well.  In some cases we can relicense portions of    #
 # DRAKVUF or grant special permissions to use it in other open source     #
 # software.  Please contact tamas.k.lengyel@gmail.com with any such       #
 # requests.  Similarly, we don't incorporate incompatible open source     #
 # software into Covered Software without special permission from the      #
 # copyright holders.                                                      #
 #                                                                         #
 # If you have any questions about the licensing restrictions on using     #
 # DRAKVUF in other works, are happy to help.  As mentioned above,         #
 # alternative license can be requested from the author to integrate       #
 # DRAKVUF into proprietary applications and appliances.  Please email     #
 # tamas.k.lengyel@gmail.com for further information.                      #
 #                                                                         #
 # If you have received a written license agreement or contract for        #
 # Covered Software stating terms other than these, you may choose to use  #
 # and redistribute Covered Software under those terms instead of these.   #
 #                                                                         #
 # Source is provided to this software because we believe users have a     #
 # right to know exactly what a program is going to do before they run it. #
 # This also allows you to audit the software for security holes.          #
 #                                                                         #
 # Source code also allows you to port DRAKVUF to new platforms, fix bugs, #
 # and add new features.  You are highly encouraged to submit your changes #
 # on https://github.com/tklengyel/drakvuf, or by other methods.           #
 # By sending these changes, it is understood (unless you specify          #
 # otherwise) that you are offering unlimited, non-exclusive right to      #
 # reuse, modify, and relicense the code.  DRAKVUF will always be          #
 # available Open Source, but this is important because the inability to   #
 # relicense code has caused devastating problems for other Free Software  #
 # projects (such as KDE and NASM).                                        #
 # To specify special license conditions of your contributions, just say   #
 # so when you send them.                                                  #
 #                                                                         #
 # This program is distributed in the hope that it will be useful, but     #
 # WITHOUT ANY WARRANTY; without even the implied warranty of              #
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   #
 # license file for more details (it's in a COPYING file included with     #
 # DRAKVUF, and also available from                                        #
 # https://github.com/tklengyel/drakvuf/COPYING)                           #
 #                                                                         #
 #*************************************************************************#

AC_PREREQ([2.60])
AC_INIT([DRAKVUF], [0.1], [tamas.k.lengyel@gmail.com], [], [http://github.com/tklengyel/drakvuf])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC_STDC
AC_PROG_CXX

# AUTOHARDEN START
# We want to check for compiler flag support, but there is no way to make
# clang's "argument unused" warning fatal.  So we invoke the compiler through a
# wrapper script that greps for this message.
saved_CC="$CC"
saved_CXX="$CXX"
saved_LD="$LD"
flag_wrap="$srcdir/scripts/wrap-compiler-for-flag-check"
CC="$flag_wrap $CC"
CXX="$flag_wrap $CXX"
LD="$flag_wrap $LD"

# We use the same hardening flags for C and C++.  We must check that each flag
# is supported by both compilers.
AC_DEFUN([check_cc_cxx_flag],
 [AC_LANG_PUSH(C)
  AX_CHECK_COMPILE_FLAG([$1],
   [AC_LANG_PUSH(C++)
    AX_CHECK_COMPILE_FLAG([$1], [$2], [$3], [-Werror $4])
    AC_LANG_POP(C++)],
   [$3], [-Werror $4])
  AC_LANG_POP(C)])
AC_DEFUN([check_link_flag],
 [AX_CHECK_LINK_FLAG([$1], [$2], [$3], [-Werror $4])])

AC_ARG_ENABLE([hardening],
  [AS_HELP_STRING([--enable-hardening],
    [Enable compiler and linker options to frustrate memory corruption exploits @<:@yes@:>@])],
  [hardening="$enableval"],
  [hardening="yes"])
AM_CONDITIONAL([HARDENING], [test x$hardening = xyes])  
  
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
    [Enable verbose debug output to be compiled @<:@no@:>@])],
  [debug="$enableval"],
  [debug="no"])   
AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

AC_ARG_WITH([xmlrpc],
      [AS_HELP_STRING([--with-xmlrpc],
         [Build DRAKVUF with Honeybrid (xmlrpc) support])],
      [with_xmlrpc=$withval],
      [with_xmlrpc=no])
AM_CONDITIONAL([XMLRPC], [test x"$with_xmlrpc" = xyes])

HARDEN_CFLAGS=""
HARDEN_LDFLAGS=""
AS_IF([test x"$hardening" != x"no"], [
  check_cc_cxx_flag([-fno-strict-overflow], [HARDEN_CFLAGS="$HARDEN_CFLAGS -fno-strict-overflow"])

#  This one will likely succeed, even on platforms where it does nothing.
  check_cc_cxx_flag([-D_FORTIFY_SOURCE=2], [HARDEN_CFLAGS="$HARDEN_CFLAGS -D_FORTIFY_SOURCE=2"])

  check_cc_cxx_flag([-fstack-protector-all],
   [check_link_flag([-fstack-protector-all],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fstack-protector-all"
      check_cc_cxx_flag([-Wstack-protector], [HARDEN_CFLAGS="$HARDEN_CFLAGS -Wstack-protector"],
        [], [-fstack-protector-all])
      check_cc_cxx_flag([--param ssp-buffer-size=1], [HARDEN_CFLAGS="$HARDEN_CFLAGS --param ssp-buffer-size=1"],
        [], [-fstack-protector-all])])])

  # At the link step, we might want -pie (GCC) or -Wl,-pie (Clang on OS X)
  #
  # The linker checks also compile code, so we need to include -fPIE as well.
  check_cc_cxx_flag([-fPIE],
   [check_link_flag([-fPIE -pie],
     [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
      HARDEN_LDFLAGS="$HARDEN_LDFLAGS -pie"],
     [check_link_flag([-fPIE -Wl,-pie],
       [HARDEN_CFLAGS="$HARDEN_CFLAGS -fPIE"
        HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-pie"])])])

  check_link_flag([-Wl,-z,relro],
   [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,relro"
    check_link_flag([-Wl,-z,now], [HARDEN_LDFLAGS="$HARDEN_LDFLAGS -Wl,-z,now"])])])

AC_SUBST([HARDEN_CFLAGS])
AC_SUBST([HARDEN_LDFLAGS])

# End of flag tests.
CC="$saved_CC"
CXX="$saved_CXX"
LD="$saved_LD"
# AUTOHARDEN END

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h stdio.h stdlib.h string.h sys/time.h sys/mman.h syslog.h unistd.h errno.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC

AC_CHECK_LIB(pthread, pthread_create, [], [AC_ERROR([Pthread library is not functional!])])

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.28], [], [AC_ERROR([glib-2.0 (version 2.28+) has to be installed!])])
AC_CHECK_LIB(glib-2.0, [g_malloc0, g_tree_lookup], [], [AC_ERROR([glib-2.0 library is not functional!])]) 

PKG_CHECK_MODULES([VMI], [libvmi >= 0.11], [], [AC_ERROR([LibVMI not found])])
AC_CHECK_HEADERS([libvmi/events.h], [], [AC_ERROR([LibVMI doesn't have events support.])], [#include <libvmi/libvmi.h>])
AC_CHECK_LIB(vmi, [vmi_register_event, vmi_step_event, vmi_read], [], [AC_ERROR([LibVMI doesn't have events support.])])

PKG_CHECK_MODULES([JANSSON], [jansson >= 2.1], [], [AC_ERROR([LibJANSSON not found])])
AC_CHECK_LIB(jansson, json_load_file, [], [AC_ERROR([LibJANSSON not usable])])

# Check for Python
AM_PATH_PYTHON([2.7])
if test "xPYTHON" != "x"; then
        AC_DEFINE_UNQUOTED(PYTHON, "$PYTHON", "Python found")
else
        AC_ERROR([Python was not found on the system!])
fi

AX_PYTHON_MODULE([pyvmi], [fatal])

AC_PATH_PROG(VOLATILITY, vol.py)

if test "x$VOLATILITY" != "x"; then
        AC_DEFINE_UNQUOTED(VOLATILITY, "$VOLATILITY", "Volatility vol.py found")
else
        AC_ERROR([** Volatility vol.py was not found in your PATH!])
fi

AC_CHECK_HEADERS([libxl_utils.h], [], [AC_ERROR([Xenlight (libxl) headers are not usable])])
AC_CHECK_LIB(xenlight, libxl_name_to_domid, [], [AC_ERROR([Xenlight does not have required features!])])

#AC_CHECK_HEADER([xenstore.h])
#AC_CHECK_LIB(xenstore, [xc_read, xs_transaction_start], [], [AC_ERROR([Xenstore not found!])])

# Check for Xenctrl and memory sharing
AC_CHECK_HEADERS([xenctrl.h], [], [AC_ERROR([XenCtrl missing! Did you install Xen yet?])])
AC_CHECK_LIB([xenctrl], 
	[xc_interface_open, xc_memshr_control, xc_memshr_nominate_gfn, xc_memshr_share_gfns], 
	[], [AC_ERROR([XenCtrl is unusable! Do you have Xen 4.2+ installed?])])

if test "x$with_xmlrpc" != "xno"; then
    AC_PATH_PROG(XMLRPC_C_CONFIG, xmlrpc-c-config)
    if test "x$XMLRPC_C_CONFIG" != "x"; then

        PKG_CHECK_MODULES([CURL], [libcurl], [
    
            XMLRPC_CLIENT_LIBS=$($XMLRPC_C_CONFIG client --libs)
            XMLRPC_CLIENT_CFLAGS=$($XMLRPC_C_CONFIG client --cflags)
    
            AC_DEFINE(HAVE_XMLRPC, 1, "Working XMLRPC C library found")
    
            AC_SUBST(XMLRPC_CLIENT_LIBS)
            AC_SUBST(XMLRPC_CLIENT_CFLAGS)
    
        ], [AC_ERROR(No CURL installed)])

    fi
fi

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

