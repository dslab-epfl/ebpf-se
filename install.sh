#!/bin/bash
# See usage().
set -eux

# Note that opam needs bash, not just sh
# Also it uses undefined variables so let's set them now otherwise it'll fail due to strict mode
if [ -z ${PERL5LIB+x} ]; then
  export PERL5LIB=''
fi
if [ -z ${MANPATH+x} ]; then
  export MANPATH=''
fi
if [ -z ${PROMPT_COMMAND+x} ]; then
  export PROMPT_COMMAND=''
fi

KLEE_RELEASE='v3.0'
KLEE_UCLIBC_RELEASE='klee_uclibc_v1.3'
LLVM_RELEASE=12
Z3_RELEASE='z3-4.8.15'

## Utility functions

# Stop script if we do not have root access
check_sudo()
{
	echo 'Checking for sudo rights:'
	if ! sudo -v;
	then
		echo 'sudo rights not obtained, or sudo not installed.' >&2;
		exit 1;
	fi
}

# Detect the running operating system
# stdout: 'windows', 'docker' or 'linux'
detect_os()
{
	# Detect WSL
	case $(uname -r) in
		*Microsoft*)
			echo 'windows'
			return 0
			;;
	esac

	# Or docker ?
	if grep docker /proc/1/cgroup -qa;
	then
		echo 'docker'
		return 0
	fi

	# Use generic "linux" tag for the rest.
	# XXX: Support some more distributions ?
	echo 'linux'
	return 0
}


# Checks if a variable is set in a file. If it is not in the file, add it with
# given value, otherwise change the value to match the current one.
# $1 : the name of the file
# $2 : the name of the variable
# $3 : the value to set
line()
{
	if grep "^export $2" "$1" >/dev/null;
	then
		# Using sed directly to change the value would be dangerous as
		# we would need to correctly escape the value, which is hard.
		sed -i "/^export $2/d" "$1"
	fi
	echo "export ${2}=${3}" >> "$1"
}

# Same as line, but without the unicity checks.
# $1 : the name of the file
# $2 : the name of the variable
# $3 : the value to set
line_multi()
{
	if ! grep "^export ${2}=${3}" "$1" >/dev/null;
	then
		echo "export ${2}=${3}" >> "$1"
	fi
}

# Install arguments using system's package manager.
# XXX: Make the package manager depend on "$OS".
# shellcheck disable=SC2086
package_install()
{
	# Concatenate arguments into a list
	old_ifs="$IFS"
	IFS=' '
	packages="$*"
	IFS="$old_ifs"

	sudo apt-get install -yqq $packages
}

# Update list of available packages.
# XXX: Make the package manager depend on "$OS".
package_sync()
{
	sudo apt-get update -qq
}

# Print script usage.
usage()
{
	cat <<- EOF
	Usage: $0 [-p <dir>] [-i <component>] [-c <component>]
	       $0 -h
	
	       When invoked with no options, $0 downloads and configures all
	       the required dependencies; else using -i and -c, one can select
	       the components to be installed or cleaned.

	       The -p option sets the directory to use as a root for the project: by default,
	       the parent of the bolt directory is used.

	       This script generates a paths.sh file that must be sourced to
	       obtain the correct working environment.

	       Components: dpdk, pin, z3, klee-uclibc, klee
	EOF
}

## Constants
CURRENTDIR="$(dirname "$(realpath "$0")")"
BUILDDIR="$(realpath -e "$CURRENTDIR"/..)"
PATHSFILE="$BUILDDIR/paths.sh"
KERNEL_VER=$(uname -r | sed 's/-Microsoft//')
OS="$(detect_os)"

INSTALL_ALL=true

CLEAN_Z3=
INSTALL_Z3=

CLEAN_LLVM=
INSTALL_LLVM=

CLEAN_KLEE_UCLIBC=
INSTALL_KLEE_UCLIBC=

CLEAN_KLEE=
INSTALL_KLEE=

## Clean and installation routines

source_install_z3()
{
	cd "$BUILDDIR"
	if [ -d 'z3/.git' ];
	then
		cd z3;
		git fetch && git checkout "$Z3_RELEASE"
	else
		git clone --depth 1 --branch "$Z3_RELEASE" https://github.com/Z3Prover/z3 "$BUILDDIR/z3"
		cd z3;
	fi

	if  [ ! -f "build/z3" ] || [ ! "z3-$(build/z3 --version | cut -f3 -d' ')" = "$Z3_RELEASE" ];	then
		python3 scripts/mk_make.py -p "$BUILDDIR/z3/build"
		cd build
		make -kj || make
		make install
	fi
}

clean_z3()
{
	cd "$BUILDDIR"
	rm -rf z3
}

bin_install_llvm()
{
	package_install clang-$LLVM_RELEASE llvm-$LLVM_RELEASE llvm-$LLVM_RELEASE-dev llvm-$LLVM_RELEASE-tools
}

clean_llvm()
{
	cd "$BUILDDIR"
	rm -rf llvm
}

source_install_klee_uclibc()
{
	cd "$BUILDDIR"
	if [ -d 'klee-uclibc/.git' ];
	then
		cd klee-uclibc
		git fetch && git checkout "$KLEE_UCLIBC_RELEASE"
	else
		git clone --depth 1 --branch "$KLEE_UCLIBC_RELEASE" https://github.com/klee/klee-uclibc.git "$BUILDDIR/klee-uclibc";
		cd klee-uclibc
	fi

	./configure \
		--make-llvm-lib \
		--with-llvm-config="/usr/bin/llvm-config-$LLVM_RELEASE" \
		--with-cc="/usr/bin/clang-$LLVM_RELEASE"

	cp "$CURRENTDIR/install/klee-uclibc.config" '.config'
	make -kj
}

clean_klee_uclibc()
{
	cd "$BUILDDIR"
	rm -rf klee-uclibc
}

source_install_klee()
{
	line "$PATHSFILE" 'KLEE_INCLUDE' "$BUILDDIR/klee/include"
	line_multi "$PATHSFILE" 'PATH' "$BUILDDIR/klee/build/bin:\$PATH"
	. "$PATHSFILE"

	cd "$BUILDDIR"
	if [ -d 'klee/.git' ];
	then
		cd klee
		git fetch && git checkout "$KLEE_RELEASE"
	else
		git clone https://github.com/klee/klee.git
		cd klee
		git checkout "$KLEE_RELEASE"
	fi
}

clean_klee()
{
	cd "$BUILDDIR"
	rm -rf klee
}

# Options
while getopts "hp:i:c:" o;
do
	case "${o}" in
	'h')
		usage;
		exit 0;
		;;
	'p')
		BUILDDIR="${OPTARG}"
		;;
	'i')
		INSTALL_ALL=
		case "${OPTARG}" in
		'z3')
			INSTALL_Z3=true
			;;
		'llvm')
			INSTALL_LLVM=true
			;;
		'klee-uclibc')
			INSTALL_KLEE_UCLIBC=true
			;;
		'klee')
			INSTALL_KLEE=true
			;;
		'*')
			echo "Unkown component to install: $OPTARG" >&2
			usage;
			exit 1;
			;;
		esac
		;;
	'c')
		INSTALL_ALL=
		case "${OPTARG}" in
		'z3')
			CLEAN_Z3=true
			;;
		'llvm')
			CLEAN_LLVM=true
			;;
		'klee-uclibc')
			CLEAN_KLEE_UCLIBC=true
			;;
		'klee')
			CLEAN_KLEE=true
			;;
		'*')
			echo "Unknown component to remove: $OPTARG" >&2
			usage;
			exit 1;
			;;
		esac
		;;
	'*')
		usage;
		exit 1;
		;;
	esac
done

# Environment
check_sudo
package_sync

# Common dependencies
package_install \
	build-essential \
	curl \
	git \
	libgoogle-perftools-dev \
	python2.7 \
	python3-minimal \
	python3-pip \
	parallel \
	gcc-multilib \
	g++-multilib \
	graphviz \
	libnuma-dev \
	cmake \
	file \
	libcap-dev \
	libncurses5-dev \
	libsqlite3-dev \
	libtcmalloc-minimal4 \
	unzip \
	doxygen \
	libelf-dev

# Clean things
[ -n "$CLEAN_Z3" ]          && clean_z3
[ -n "$CLEAN_LLVM" ]        && clean_llvm
[ -n "$CLEAN_KLEE_UCLIBC" ] && clean_klee_uclibc
[ -n "$CLEAN_KLEE" ]        && clean_klee

# Install things
{ [ -n "$INSTALL_ALL" ] || [ -n "$INSTALL_Z3" ]   ; } && source_install_z3
{ [ -n "$INSTALL_ALL" ] || [ -n "$INSTALL_LLVM" ] ; } && bin_install_llvm
{ [ -n "$INSTALL_ALL" ] || [ -n "$INSTALL_KLEE_UCLIBC" ] ; } && source_install_klee_uclibc
{ [ -n "$INSTALL_ALL" ] || [ -n "$INSTALL_KLEE" ] ; } && source_install_klee
