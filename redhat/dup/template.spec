%define kmod_name		DUP_KMOD_NAME
%define kmod_driver_version	DUP_KMOD_DRIVER_VERSION
%define kmod_rpm_release	DUP_KMOD_RPM_RELEASE
%define kmod_kernel_version	DUP_KMOD_KERNEL_KVERSION
%define kmod_suffix		rhel6u0

%{!?dist: %define dist .el6}

Source0:	%{kmod_name}-%{kmod_driver_version}.tar.bz2
Source1:	%{kmod_name}.files
Source2:	%{kmod_name}.conf

Name:		%{kmod_name}
Version:	%{kmod_driver_version}
Release:	%{kmod_rpm_release}%{?dist}
Summary:	%{kmod_name} kernel module

Group:		System/Kernel
License:	GPLv2
URL:		http://www.kernel.org/
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:	%kernel_module_package_buildreqs
ExclusiveArch:  i686 x86_64

# Uncomment to build "debug" packages
#kernel_module_package -f %{SOURCE1} default debug

# Build only for standard kernel variant(s)
%kernel_module_package -f %{SOURCE1} default

%description
%{kmod_name} - driver update

%prep
%setup
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build; do
	rm -rf obj/$flavor
	cp -r source obj/$flavor
	make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build ; do
	make -C %{kernel_source $flavor} modules_install \
		M=$PWD/obj/$flavor
	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
done

install -m 644 -D %{SOURCE2} $RPM_BUILD_ROOT/etc/depmod.d/%{kmod_name}.conf

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* DUP_DATE DUP_AUTHOR DUP_KMOD_DRIVER_VERSION DUP_KMOD_RPM_RELEASE
- DUP_KMOD_NAME DUP module
