Source: capylink-server
Section: net
Priority: optional
Maintainer: open-trade <info@rustdesk.com>
Build-Depends: debhelper (>= 10), pkg-config
Standards-Version: 4.5.0
Homepage: https://rustdesk.com/

Package: capylink-server-hbbs
Architecture: {{ ARCH }}
Depends: systemd ${misc:Depends}
Description: capylink server
 Self-host your own capylink server, it is free and open source.

Package: capylink-server-hbbr
Architecture: {{ ARCH }}
Depends: systemd ${misc:Depends}
Description: capylink server
 Self-host your own capylink server, it is free and open source.
 This package contains the capylink relay server.

Package: capylink-server-utils
Architecture: {{ ARCH }}
Depends: ${misc:Depends}
Description: capylink server
 Self-host your own capylink server, it is free and open source.
 This package contains the capylink-utils binary.
