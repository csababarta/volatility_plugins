Volatility plugins created by the author

The plugins published here can be used with Volatility v2.4.

BASELINE plugin suite
=====================
  PROCESSBL    A plugin that compares the running processes in 2 memory images
               - can be used to detect newly started processes
               - can be used to detect newly loaded DLLs
               
  SERVICESBL   A plugin that compares the services in 2 memory images
               - can be used to detect modification of service configuration
               - can be used to detect newly installed services
               
  DRIVERBL     A plugin that compares the kernel drivers in 2 memory images
               - can be used to detect newly installed / loaded drivers

MALPROCFIND
===========

A plugin that searches for malicious processes based predefined rules.

Output types: text
             
INDX
====

A plugin that carves for and parses INDX ($I30) entries

Output types: text, body

USNJRNL
=======

A plugin that carves for and parses USNJRNL ($J) entries

Output types: text, body

LOGFILE
=======

A plugin that carves for and parses $Logfile entries. It will process the
following entry types:

 - UPDATE FILENAME ALLOCATION (Partial FILENAME Attributes)
 - ADD INDEX ENTRY ALLOCATION (INDX Records)
 - DELETE INDEX ENTRY ALLOCATION (INDX Records)
 - INITIALIZE FILE RECORD SEGMENT (MFT FILE0 Records)
 - DEALLOCATE FILE RECORD SEGMENT (MFT FILE0 Records)

Output types: text, body