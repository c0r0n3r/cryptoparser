Name:           python-cryptoparser
Version:        1.2.1
Release:        1%{?dist}
Summary:        Multi-protocol cryptographic protocol parser library

License:        MPL-2.0
URL:            https://gitlab.com/coroner/cryptoparser
Source0:        %{name}_%{version}.tar.xz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  python3-cryptodatahub >= 1.2.1

%description
CryptoParser is a library for parsing cryptographic protocol messages
including TLS, SSH, IKE, and related protocols. It is used as the
parsing backend for CryptoLyzer.

%package -n python3-cryptoparser
Summary:        %{summary}
Requires:       python3-asn1crypto
Requires:       python3-attrs
Requires:       python3-cryptodatahub >= 1.2.1
Requires:       python3-urllib3

%description -n python3-cryptoparser
CryptoParser is a library for parsing cryptographic protocol messages
including TLS, SSH, IKE, and related protocols. It is used as the
parsing backend for CryptoLyzer.

%prep
%setup -q -T -c -n %{name}-%{version}
tar -xJf %{SOURCE0} --strip-components=1
sed -i "s/, 'setuptools-scm'//" pyproject.toml
sed -i "s/name = 'CryptoParser'/name = 'cryptoparser'/" pyproject.toml
sed -i "s/exclude = \['submodules'\]/include = ['cryptoparser*']/" pyproject.toml

%build
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}

%install
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}
%{__python3} -m pip install --no-build-isolation --no-deps --root %{buildroot} --prefix %{_prefix} .
%check

%files -n python3-cryptoparser
%{python3_sitelib}/cryptoparser/
%{python3_sitelib}/cryptoparser-%{version}.dist-info/
%license LICENSE.txt
