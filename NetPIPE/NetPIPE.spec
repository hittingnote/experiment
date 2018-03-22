Summary: Protocol independent performance tool
Name: NetPIPE
Version: 3.7.1
Release: 2.0.7%{?dist}
License: GPL+
Group: Applications/Internet
URL: http://bitspjoule.org/netpipe/

Source: http://bitspjoule.org/netpipe/code/NetPIPE-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: libibverbs-devel

%description
NetPIPE is a protocol independent performance tool that visually represents
the network performance under a variety of conditions. It performs simple
ping-pong tests, bouncing messages of increasing size between two processes,
whether across a network or within an SMP system. Message sizes are chosen
at regular intervals, and with slight perturbations, to provide a complete
test of the communication system. Each data point involves many ping-pong
tests to provide an accurate timing. Latencies are calculated by dividing
the round trip time in half for small messages ( < 64 Bytes ).

%prep
%setup -q 
make clean

%build
make %{?_smp_mflags} memcpy tcp ibv \
	CFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf %{buildroot}
chmod 0644 dox/*

install -Dp -m0755 bin/feplot  %{buildroot}%{_bindir}/feplot
install -Dp -m0755 bin/geplot  %{buildroot}%{_bindir}/geplot
install -Dp -m0755 bin/nplaunch  %{buildroot}%{_bindir}/nplaunch
install -Dp -m0755 NPmemcpy %{buildroot}%{_bindir}/NPmemcpy
install -Dp -m0755 NPtcp %{buildroot}%{_bindir}/NPtcp
install -Dp -m0755 NPibv %{buildroot}%{_bindir}/NPibv
install -Dp -m0644 dox/netpipe.1 %{buildroot}%{_mandir}/man1/netpipe.1

%clean
rm -rf %{buildroot}

%files
%defattr(-, root, root, -)
%doc dox/netpipe_paper.ps  dox/README dox/np_cluster2002.pdf dox/np_euro.pdf
%doc %{_mandir}/man1/netpipe.1*
%{_bindir}/*

%changelog
* Wed Jul 28 2010 Paul Morgan <jumanjiman@gmail.com> 3.7.1-2.0.7
- git now ignores binaries left over from build process (jumanjiman@gmail.com)
- Updated SPEC-File with a couple of cleanups (fedora-package@jens.kuehnel.org)

* Wed Jul 28 2010 "Jens Kuehnel <fedora-package@jens.kuehnel.org>" - 3.7.1-2.0.6
- put all binaries/scripts into _bindir

* Wed Jul 28 2010 "Jens Kuehnel <fedora-package@jens.kuehnel.org>" - 3.7.1-2.0.5
- remove ibv from version string (not compatible with Fedora Package Guideline)
- remove NPmpi because of broken mpicc

* Wed Jul 28 2010 Paul Morgan <jumanjiman@gmail.com> 3.7.1.ibv-2.0.5
- removed requires for libibverbs (jumanjiman@gmail.com)

* Wed Jul 28 2010 Paul Morgan <jumanjiman@gmail.com> 3.7.1.ibv-2.0.4
- add binaries NPibv and NPmpi to install section of spec

* Wed Jul 28 2010 Paul Morgan <pmorgan@redhat.com> 3.7.1.ibv-2.0.3
- version now uses .ibv (pmorgan@redhat.com)
- requires libibverbs (pmorgan@redhat.com)

* Wed Jul 28 2010 Paul Morgan <jumanjiman@gmail.com> 3.7.1-2.0.2
- new package built with tito and ibverbs support

* Wed Jul 28 2010 Jens Kuehnel <fedora-package@jens.kuehnel.org> - 3.7.1-2.0.1
- add ibvers support
* Thu Oct 15 2009 Scott Collier <boodle11@gmail.com> - 3.7.1-2
- Cleaned up spec file
* Mon Oct 14 2009 Scott Collier <boodle11@gmail.com> - 3.7.1-1.2
- changed: buildroot
- added: -q to setup
- added: %{?dist} tag to release field
- modified: CFLAGS
- fixed perms on netpipe.spec
- removed obsoletes line
- removed executable perms on docs files
* Mon Sep 12 2009 Scott Collier <boodle11@gmail.com> - 3.7.1-1.2
- Rebuild for Fedora

