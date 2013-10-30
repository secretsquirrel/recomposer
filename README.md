Recomposer.py
==========

Ever have that not so safe feeling uploading your malware binaries to VirusTotal or other AV sites because you can look up binaries by hashes?  (Example: https://github.com/mubix/vt-notify)

Feel somewhat safer with Recomposer!*

Recomposer will take your binary and randomly do the following:

* Change the file name
* Change the section names
* Change the section flags
* Injection random number of five different types of nops into each available code cave over 20 bytes in length

By the way, your file will still execute, so upload away!*

**Supports win32/64 PE Files!!**

Two modes:

* Manual: Works like a PE Editor, change section names and flags
* Auto: Randomly changes the binary

Tested by creating 11200 samples from one binary. Results:

* No hash collisions
* ssdeep matching percentage to the original file ranged from 94% to 77%

# **Usage:** 

## Auto Mode:
	
	./recomposer.py -f live.sysinternals.com/Tcpview.exe -a
	Old file name: live.sysinternals.com/Tcpview.exe
	New file name: zYmycO4NO2LYW.exe
	[*] Checking if binary is supported
	[*] Gathering file info
	1 Section: .text | SectionFlags: 0x60000020
	2 Section: .rdata | SectionFlags: 0x40000040
	3 Section: .data | SectionFlags: 0xc0000040
	4 Section: .rsrc | SectionFlags: 0x40000040
	[*] Changing Section .text Name
	[*] Changing Section .rdata Name
	[*] Changing Section .data Flags
	[*] Changing Section .data Name
	[*] Changing Section .rsrc Name
	Updated Binary:
		updatedfile/zYmycO4NO2LYW.exe
	[*] Checking if binary is supported
	[*] Gathering file info
	1 Section: .mhz | SectionFlags: 0x60000020
	2 Section: .p1k | SectionFlags: 0x40000040
	3 Section: .FSr0U | SectionFlags: 0xd0000443
	4 Section: .q2X | SectionFlags: 0x40000040
	Writing to log_recomposer.txt

You might see this warning:
	
	[!] Warning, .text section hash is not changed!
	[!] No caves available for nop injection.

Which means that the .text section hash will be the same as the original file and be searchable (on the web) once google indexes the VT results (if you upload the file of course).  If this happens, upx encoding the recomposed file should take care of that problem (unless the file is already upx encoded).

After recomposer completes, your file will be in the updatedfile directory. Feel free to upload it to your favorite malware sandbox service!

## Manual Mode:

A simple PE Editor:	

	./recomposer.py -f live.sysinternals.com/Tcpview.exe -m
	[*] Checking if binary is supported
	[*] Gathering file info
	[?] What sections would you like to change:
	1 Section: .text | SectionFlags: 0x60000020
	2 Section: .rdata | SectionFlags: 0x40000040
	3 Section: .data | SectionFlags: 0xc0000040
	4 Section: .rsrc | SectionFlags: 0x40000040
	Section number:1
	[-] You picked the .text section.
	[?] Would you like to (A) change the section name or (B) the section flags? b
	[-] You picked: b
	=========================
	[*] Current attributes:
	.text | 0x60000020
	[-] IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_EXECUTE
	[-] IMAGE_SCN_CNT_CODE
	=========================
	[*] Commands 'zero' out the flags, 'help', 'write', or ('exit', 'quit', 'q', 'done')
	[*] Use 'write' to commit your changes or 'clear' to start over.
	[?] Enter an attribute to add or type 'help' or 'exit': 
	[...]

Just follow the menu and your results will be in updatedfile directory as change.filename.exe or whatever the output you chose when using the -o flag.

If you are confused about where your files are, just look at log_recomposer.txt for location and hashes of files changed:
	
	filename|filename_hash|changedfile|changedfile_hash
	
	psinfo.exe|ae1554f2c1b1454a91c5610747603824|updatedfile/8dV5.exe|791ff4d4b2010accebc718afda58f83a
	psexec.exe|d0df366711c8b296680002840336b6fd|updatedfile/udi6ieIVFi.exe|6fafa108d697a46a271a918436e60cd5
	live.sysinternals.com/Tcpview.exe|9aa5a93712c584acdcaa7eef9d25ef4d|updatedfile/zYmycO4NO2LYW.exe|fd984b833443c457668a480a37cf9904
	live.sysinternals.com/Tcpview.exe|9aa5a93712c584acdcaa7eef9d25ef4d|updatedfile/change.Tcpview.exe|c43eeec089a3e4f9e6fd0218a27ca4c2


\*Recomposer does not stop malware from notifying the malware owner of their binary running outside of an expected environment.\*\*


\*\*I.E.: Your environment.\*\*\*

\*\*\*But if you don't care, go for it!