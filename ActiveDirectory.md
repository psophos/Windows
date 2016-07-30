#Active Directory

##Domain Name System (DNS)

	http://blogs.technet.com/b/askpfeplat/archive/2013/10/12/who-moved-the-dns-cheese-auditing-for-ad-integrated-dns-zone-and-record-deletions.aspx
	https://blogs.technet.microsoft.com/networking/2008/03/19/dont-be-afraid-of-dns-scavenging-just-be-patient/
	http://blogs.technet.com/b/askpfeplat/archive/2015/09/28/finding-pesky-stale-dns-srv-records.aspx { DC rename/replacement }
		http://blogs.technet.com/b/ashleymcglone/archive/2010/12/22/a-dickens-of-a-dns-puzzle-how-to-clean-up-those-stale-ad-site-dns-records.aspx

[How to do DNS correctly](http://blog.gdwnet.com/2015/07/how-to-do-dns-correctly.html)

[Configuring DNS on domain controllers](http://www.windowsnetworking.com/articles-tutorials/windows-server-2012/active-directory-insights-part1.html)
{ Active Directory Insights (Part 1) +++ }

[How 'netmask ordering' feature in DNS affects the resultant queries](http://blogs.technet.com/b/askpfeplat/archive/2013/02/18/how-netmask-ordering-feature-in-dns-affects-the-resultant-queries.aspx)

[How Often Does the DNS Server Service Check AD for New or Modified Data?](http://blogs.technet.com/b/askpfeplat/archive/2013/03/22/mailbag-how-often-does-the-dns-server-service-check-ad-for-new-or-modified-data.aspx)

[How To Split and Migrate Child Domain DNS Records To a Dedicated DNS Zone](http://blogs.technet.com/b/askpfeplat/archive/2013/12/02/how-to-split-and-migrate-child-domain-dns-records-to-a-dedicated-dns-zone.aspx)

###DNS Search Order {DNS suffix configuration}

You need to add `new_domain.com` to the suffix search list of your computers.

You can do this either by configuring DHCP as described here:
[DHCP Search Options](https://technet.microsoft.com/en-us/library/dd572752(v=office.13).aspx)

or you can use a GPO to set it

[Manage DNS suffix configuration through Group Policy](http://www.techrepublic.com/blog/the-enterprise-cloud/manage-dns-suffix-configuration-through-group-policy/)

>The **DNS suffix** is one of the most important settings on a server's network configuration, yet it is so easy to omit
because the value is buried deep within the DNS tap of networking configuration. There are a number of ways to ensure
consistent configuration of the DNS suffix, including using Group Policy.

By using both you can make sure that most systems e.g. dhcp clients, and static IP'd servers can connect to the remote domain resources using the "short" NetBIOS name.

https://community.spiceworks.com/topic/1397227-ad-trust-established-but-cannot-ping-the-host-name


###SRV Records

A DNS SRV record identifies a server where a services exists, and what services exist on a server.

Clients will know as a function of the logon process which site they are in.

	[_kerberos|_ldap]._tcp.<sitename>._sites.dc._msdcs.domain.com

The **weight** option on the SRV record controls use of servers when requesting services.

From: finding-pesky-stale-dns-srv-records

>We can use the `netlogon.dns` file found in C:\windows\system32\config folder to find out what records should be present if the DC is operational.

[The DC Locator Process, The Logon Process, Controlling Which DC Responds in an AD Site, and SRV Records](http://blogs.msmvps.com/acefekay/2010/01/03/the-dc-locator-process-the-logon-process-controlling-which-dc-responds-in-an-ad-site-and-srv-records/)

[Setup: AD sites, subnets, site-links](http://www.rebeladmin.com/2015/02/how-to-setup-active-directory-sites-subnets-site-links/)

To find out which DC logged you in:

	echo %logonserver%

You can also test which DCs are nearest to your workstation in your site (copy nltest.exe from the DC to the workstation’s system32 folder):

	nltest /sc_query:YourDomainName.com

To find the GC your workstation used (copy nltest.exe from the DC to the workstation's system32 folder):

	nltest /dgsgetdc:your_domain_name.com /GC

[DNS Records that are required for proper functionality of Active Directory](https://blogs.msdn.microsoft.com/servergeeks/2014/07/12/dns-records-that-are-required-for-proper-functionality-of-active-directory/)

[How to verify that SRV DNS records have been created for a domain controller](https://support.microsoft.com/en-ie/kb/816587)

DNS Management Console to verify that the appropriate zones and resource records are created for each DNS zone.

Active Directory creates its SRV records in the following folders, where Domain_Name is the name of your domain:

	Forward Lookup Zones/Domain_Name/_msdcs/dc/_sites/Default-First-Site-Name/_tcp
	Forward Lookup Zones/Domain_Name/_msdcs/dc/_tcp

In these locations, an SRV record should appear for the following services:

	_kerberos
	_ldap

View Netlogon.dns : Netlogon.dns is located in the `%systemroot%\System32\Config` folder.

The first record in the file is the domain controller's LDAP SRV record. Similar to the following:

	_ldap._tcp.Domain_Name

Nslookup

	set type=all
	_ldap._tcp.dc._msdcs.Domain_Name

####Registered SRV records

######TODO: Carve this out into another doc

{registered by: All Windows 2000 Server–based DCs}

Locate a server that is running the LDAP service (not necessarily a DC).

	_ldap._tcp.DnsDomainName.

Locate a server that is running the LDAP service in the site named (not necessarily a DC).

	_ldap._tcp.SITENAME._sites.DnsDomainName.

Locate a DC {registered by: All Windows 2000 Server–based DCs}

	_ldap._tcp.dc._msdcs.DnsDomainName.

Locate a DC in a site.

	_ldap._tcp.SITENAME._sites.dc._msdcs.DnsDomainName.

Locate the server that is acting as the PDCe in the mixed-mode domain. {registered by: the PDCe}

	_ldap._tcp.pdc._msdcs.DnsDomainName.

Locate a GC server for this forest. {registered by: DCs that are functioning as GCs servers for the forest}

	_ldap._tcp.gc._msdcs.DnsForestName.

Locate a GC server for this forest in the site. {registered by: DCs that are serving as GCs for the forest}

	_ldap._tcp.SITENAME._sites.gc._msdcs.DnsForestName.

Locate a GC server for this domain (not necessarily a DC). {registered by: servers running the LDAP service and functioning as the GC for the forest}

	_gc._tcp.DnsForestName.

Locate a GC server for this forest in the site named (not necessarily a DC). {registered by: server running the LDAP service and functioning as the GC forest}

	_gc._tcp.SITENAME._sites.DnsForestName.

Locate a DC in a domain on the basis of its GUID. {registered by: all DCs}

	_ldap._tcp.DomainGuid.domains._msdcs.DnsForestName.

Locate a server that is running the Kerberos KDC service for the domain (not necessarily a DC). {registered by: All Windows 2000 Server–based DCs running an RFC 1510–compliant Kerberos KDC service}

	_kerberos._tcp.DnsDomainName.

Same as _kerberos._tcp.DnsDomainName, except that UDP is implied.

	_kerberos._udp.DnsDomainName.

_kerberos._tcp.SITENAME._sites.DnsDomainName.
Locate a server that is running the Kerberos KDC service for the domain in the site (not necessarily a DC). {registered by: All Windows 2000 Server–based DCs running an RFC 1510–compliant Kerberos KDC service}


Locate a DC that is running the Windows 2000 implementation of the Kerberos KDC service for the domain.
{registered by: All Windows 2000 Server–based DCs running the KDC service (that is, that implement a public key extension to the Kerberos v5 protocol Authentication Service Exchange subprotocol)}

	_kerberos._tcp.dc._msdcs.DnsDomainName.

Locate a DC that is running the Windows 2000 implementation of the Kerberos KDC service for the domain in the site.
{registered by: All Windows 2000 Server–based DCs running the KDC service (that is, that implement a public key extension to the Kerberos v5 protocol Authentication Service Exchange subprotocol)}

	_kerberos.tcp.SITENAME._sites.dc._msdcs.DnsDomainName.

Locate a Kerberos Password Change server for the domain (not necessarily a DC)
{registered by: All servers that provide the Kerberos Password Change service}
{registered by: All Windows 2000 Server–based DCs running an RFC 1510–compliant Kerberos KDC service}

	_kpasswd._tcp.DnsDomainName.

Same as _kpasswd._tcp.DnsDomainName, except that UDP is implied.

	_kpasswd._udp.DnsDomainName.


Net Logon registers DNS A records for the use of LDAP clients that do not support DNS SRV records. The Locator does not use these records.


Windows Vista/2008 and above; DC Locator Improvements

Windows Vista and newer, allows auto-rediscovery if their original logon server is no longer available:

Vista/2008: forcing DC rediscover

	nltest /dsgetdc:<FQDN Domain Name> /force


###DNS Misc:

[Enable DNS Request Logging for Windows 2003 and above](https://support.appriver.com/kb/a669/enable-dns-request-logging-for-windows-2003-and-above.aspx)

How can I monitor if there are applications still using my domain?

[Domain and DC Migrations: How To Monitor LDAP, Kerberos and NTLM Traffic To Your Domain Controllers](http://blogs.technet.com/b/askpfeplat/archive/2013/12/16/domain-and-dc-migrations-how-to-monitor-ldap-kerberos-and-ntlm-traffic-to-your-domain-controllers.aspx)

[Multihomed DCs with DNS, RRAS, and/or PPPoE adapters](http://blogs.msmvps.com/acefekay/2009/08/17/multihomed-dcs-with-dns-rras-and-or-pppoe-adapters/)

To check the SRV records:

* On your DNS Server;
* Open command prompt, Type: `nslookup`, and then press ENTER.
* Type: `set type=all`, and then press ENTER.
* Type: _ldap._tcp.dc._msdcs.Domain_Name  - where Domain_Name is the DNS name of your domain


[Using Catch-All Subnets in Active Directory](https://technet.microsoft.com/en-nz/magazine/2009.06.subnets%28en-us%29.aspx) - How Clients Locate Domain Controllers


##Troubleshooting AD

###RepAdmin
[How To Use Repadmin for Active Directory Troubleshooting](https://redmondmag.com/articles/2014/08/08/repadmin-for-ad-troubleshooting.aspx)

###DcDiag

>Analyzes the state of domain controllers in a forest or enterprise and reports any problems to help in troubleshooting.

As an end-user reporting program, **_[dcdiag](https://technet.microsoft.com/en-us/library/cc731968.aspx)_** is a
command-line tool that encapsulates detailed knowledge of how to identify
abnormal behavior in the system. Dcdiag displays command output at the command prompt.

	dcdiag /e /c /f:dcdiag.log   [/v gives verbose output]
	dcdiag test:DNS /e /v /f:dns.txt

Check DNS

	dcdiag /test:dns /dnsall /v >DNSTEST.log

Check AD

	dciag /v /c >DCTEST.LOG

[What does dcdiag actually do?](http://blogs.technet.com/b/askds/archive/2011/03/22/what-does-dcdiag-actually-do.aspx)

[Domain Controller Diagnostics Tool: dcdiag.exe](https://technet.microsoft.com/en-us/library/cc776854%28v=ws.10%29.aspx)

There are various errors using the Windows Server 2003/2008/200R2 versions of DCDIAG:
[DCDIAG.EXE /E or /A or /C expected errors](https://support.microsoft.com/en-us/kb/2512643/)

[Active Directory: Mixing Server 2003 DCs and Server 2012 DCs May Result In Kerberos Authentication Errors](http://blogs.technet.com/b/askds/archive/2014/07/23/it-turns-out-that-weird-things-can-happen-when-you-mix-windows-server-2003-and-windows-server-2012-r2-domain-controllers.aspx)
{ hotfix is available for Server 2012r2 }

###Performance

[Reducing the workload on the PDC emulator master](https://technet.microsoft.com/en-us/library/cc787370%28WS.10%29.aspx)

- [Adjusting the Weight for DNS SRV Records in the Registry](https://technet.microsoft.com/en-us/library/cc778225%28v=ws.10%29.aspx)
- [Adjusting the Priority for DNS SRV Records in the Registry](https://technet.microsoft.com/en-us/library/cc781155%28v=ws.10%29.aspx)

Article is dated 2005, appears to be for Server 2003. Might still have some relevance.

[Are your DCs too busy to be monitored?: AD Data Collector Set solutions for long report compile times or report data deletion](https://blogs.technet.microsoft.com/askds/2016/04/14/are-your-dcs-too-busy-to-be-monitored-ad-data-collector-set-solutions-for-long-report-compile-times-or-report-data-deletion/)

[Son of SPA: AD Data Collector Sets in Win2008 and beyond](https://blogs.technet.microsoft.com/askds/2010/06/08/son-of-spa-ad-data-collector-sets-in-win2008-and-beyond/)

How to gather Active Directory Diagnostics from the command line

To START a collection of data from the command line issue this command from an elevated command prompt:

	logman start "system\Active Directory Diagnostics" -ets

To STOP the collection of data before the default 5 minutes, issue this command:

	logman stop "system\Active Directory Diagnostics" -ets

NOTE: To gather data from remote systems just add “-s servername” to the commands above like this:

	logman -s servername start "system\Active Directory Diagnostics" -ets

	logman -s servername stop "system\Active Directory Diagnostics" -ets


##AD Replication

###Troubleshooting Active Directory Replication Problems

[Server 2008](https://technet.microsoft.com/en-us/library/cc949120%28v=ws.10%29.aspx)

[Server 2003](https://technet.microsoft.com/en-us/library/cc738415%28v=ws.10%29.aspx)

[Checking Active Directory Replication Using PowerShell](http://www.serverwatch.com/server-tutorials/checking-active-directory-replication-using-powershell.html)


###Monitor AD Replication Status

[AD Replication Status Tool](http://blogs.technet.com/b/askds/archive/2012/08/23/ad-replication-status-tool-is-live.aspx)

[Active Directory Replication Status Tool: Now in Operations Management Suite](https://mms.microsoft.com/Content/AdvisorCore/Html/ADReplication.htm)


###DFSR

[Best practices for DFS-R on Domain Controllers](http://blogs.technet.com/b/askpfeplat/archive/2013/08/09/friday-mailbag-best-practices-for-dfs-r-on-domain-controllers.aspx)

[Fixing Broken SYSVOL Replication - Replicating SYSVOL by using DFSR](http://windowsitpro.com/windows-server-2012/fixing-broken-sysvol-replication) { DFSR }

[How to force an authoritative and non-authoritative synchronization for DFSR-replicated SYSVOL](https://support.microsoft.com/en-us/kb/2218556)
{ like "D4/D2" for FRS }

[How to troubleshoot journal_wrap errors on Sysvol and DFS replica sets](https://support.microsoft.com/en-us/kb/292438) { DFSR }

[Understanding DFSR Dirty (Unexpected) Shutdown Recovery](http://blogs.technet.com/b/filecab/archive/2012/07/23/understanding-dfsr-dirty-unexpected-shutdown-recovery.aspx)
{ DFSR }

[DFS Replication: How to troubleshoot missing SYSVOL and Netlogon shares](https://support.microsoft.com/en-ie/kb/2958414)

[Implementing Content Freshness protection in DFSR](http://blogs.technet.com/b/askds/archive/2009/11/18/implementing-content-freshness-protection-in-dfsr.aspx)

>If a DFSR server cannot replicate an Replicated Folder (RF) for more than 60 days, but then replication is allowed later,
it can replicate out old deletions for files that are actually live or replicate out stale data and overwrite existing files.
Content Freshness (per server setting) should prevent this.

[SYSVOL and Group Policy out of Sync on Server 2012 R2 DCs using DFSR](http://jackstromberg.com/2014/07/sysvol-and-group-policy-out-of-sync-on-server-2012-r2-dcs-using-dfsr/)


###FRS

[It's The End of FRS as We Know It (And I Feel Fine)](http://blogs.technet.com/b/askpfeplat/archive/2014/06/24/it-s-the-end-of-frs-as-we-know-it-and-i-feel-fine.aspx)

[How to rebuild the SYSVOL tree and its content in a domain](https://support.microsoft.com/en-us/kb/315457)
{ FRS, Burflags }

[Using the BurFlags registry key to reinitialize File Replication Service replica sets](https://support.microsoft.com/en-us/kb/290762) { FRS }

[Authoritative SYSVOL restore](http://kpytko.pl/active-directory-domain-services/authoritative-sysvol-restore-frs/)
{ FRS }

[Non-authoritative SYSVOL restore](http://kpytko.pl/active-directory-domain-services/non-authoritative-sysvol-restore-frs/)
Applies to the Server that is out of sync { FRS }

[Ultrasound - Monitoring and Troubleshooting Tool for File Replication Service](https://www.microsoft.com/en-us/download/details.aspx?id=3660)
{ FRS }

[Verifying File Replication during the Windows Server 2008 DFSR SYSVOL Migration - Down and Dirty Style](https://blogs.technet.com/b/askds/archive/2008/05/22/verifying-file-replication-during-the-windows-server-2008-dfsr-sysvol-migration-down-and-dirty-style.aspx).

This post will not be about Ultrasound. Instead, I am going to use a combination of `FRSDIAG` and the `DFSR` Propagation tool.
This is not as sophisticated as using Ultrasound, but it’s considerably simpler and easier – both good selling points.


[What happens in a Journal Wrap?](http://blogs.technet.com/b/instan/archive/2009/07/14/what-happens-in-a-journal-wrap.aspx)
{ FRS - Sysvol not shared }


####Events:

[DFSR event ID 2213 in Windows Server 2008 R2 or Windows Server 2012](https://support.microsoft.com/en-ie/kb/2846759)

>DFS Replication (DFSR) service for Windows Server 2008 R2 through hotfix 2663685. After you install hotfix 2663685 or a later version of
Dfsrs.exe in Windows Server 2008 R2, the DFSR Service no longer performs automatic recovery of the Extensible Storage Engine (ESE)) database
after the database experiences a dirty shutdown. Instead, when the new DFSR behavior is triggered, event ID 2213 is logged in the DFSR log.
A DFSR administrator must manually resume replication after a dirty shutdown is detected by DFSR.

>Windows Server 2012 exhibits this behavior by default.

	Event Type: Warning
	Event Source: DFSR
	Event Category: Disk
	Event ID: 2213
	Description:
	"The DFS Replication service stopped replication on volume C. This occurs when a DFSR JET database is not shut down cleanly and
	Auto Recovery is disabled. To resolve this issue, back up the files in the affected replicated folders, and then use the
	ResumeReplication WMI method to resume replication.

	Event Type: Warning
	Event Source: DFSR
	Event Category: Disk
	Event ID: 2212
	Description:
	"The DFS Replication service has detected an unexpected shutdown on volume E:. This can occur if the service terminated abnormally
	(due to a power loss, for example) or an error occurred on the volume. The service has automatically initiated a recovery process.
	The service will rebuild the database if it determines it cannot reliably recover. No user action is required.

	Event Type: Warning
	Event Source: DFSR
	Event Category: Disk
	Event ID: 2214
	Description:
	"The DFS Replication service successfully recovered from an unexpected shutdown on volume E:.This can occur if the service terminated
	abnormally (due to a power loss, for example) or an error occurred on the volume. No user action is required.


###SYSVOL

[SYSVOL migration from FRS to DFSR](http://blogs.technet.com/b/askds/archive/2009/05/01/sysvol-migration-from-frs-to-dfsr-whitepaper-released.aspx)

[Streamlined Migration of FRS to DFSR SYSVOL](http://blogs.technet.com/b/filecab/archive/2014/06/25/streamlined-migration-of-frs-to-dfsr-sysvol.aspx)

[SYSVOL Replication Migration Guide: FRS to DFS Replication](http://technet.microsoft.com/en-us/library/dd640019%28WS.10%29.aspx) { comprehensive guide - 2010-08 }

[The Case for Migrating SYSVOL to DFSR](https://blogs.technet.microsoft.com/askds/2010/04/22/the-case-for-migrating-sysvol-to-dfsr/)

Domain controllers use a special shared folder named _SYSVOL_ to replicate logon scripts and Group Policy object files to other domain controllers.
Windows 2000 Server and Windows Server 2003 use File Replication Service (FRS) to replicate SYSVOL, whereas Windows Server 2008 uses the newer DFS
Replication service when in domains that use the Windows Server 2008 domain functional level, and FRS for domains that run older domain functional levels.

>All DCs need to be upgraded to Server 2008 so that the **DFL** can be incremented to **Windows Server 2008**.
Even after this upgrade is done, FRS will still be the replication engine for SYSVOL, until the SYSVOL migration procedure is initiated by the administrator.

>NOTE:  The Windows Server 2008 SP2 release includes a couple of important bug-fixes in DFS Replication that address a few customer reported issues in SYSVOL migration.
If you plan to migrate replication of the SYSVOL share to DFS Replication, it is highly recommended that you upgrade to Windows Server 2008 SP2 first.

>The RTM release of Windows Server 2008 R2 includes these bug fixes.

[Overview of the SYSVOL Migration Procedure](http://technet.microsoft.com/en-us/library/dd639809%28WS.10%29.aspx)

[Best practices for DFS-R on Domain Controllers](http://blogs.technet.com/b/askpfeplat/archive/2013/08/09/friday-mailbag-best-practices-for-dfs-r-on-domain-controllers.aspx) { 2013-08 }

From a DC:

	dfsrmig /GetGlobalState     # Get the current global dfsr migration state
	dfsrmig /GetMigrationState  # Shows the progress of migration accross all DCs.

	dfsrmig /SetGlobalState <state>  # Set the current global dfsr migration state

* `<state>` equates to:
	* 0 - 'Start'
	* 1 - 'Prepared'
	* 2 - 'Redirected'
	* 3 - 'Eliminated'


####Migrating to the 'Prepared' State

- Verify the health of Active Directory Domain Services
- Raise the domain functional level to Windows Server 2008
- Migrate the domain to the Prepared state
- Verify that the domain has migrated to the Prepared state

http://technet.microsoft.com/en-us/library/dd641193%28WS.10%29.aspx

Health checks:

Make sure you have sufficient free disk space for the migration:

	gwmi -class Win32_LogicalDisk -ComputerName <DC_name>

	Get-ADDOmainController -Server <DC_name> -Filter *

Start the process by moving to State 1

	dfsrmig /SetGlobalState 1

Then, **_WAIT!_**  Seriously, be patient.

Check the status of the migration using:

	dfsrmig /GetMigrationState

Only when the GetMigrationState command informs you that you have fully reached state 1 'Prepared' should you then proceed to state 2.

Force push replication of all AD partitions, ignoring any schedules (bit of a sledgehammer approach).

	repadmin /syncall /force /aped <DC_name>

Run after AD has reconverged due to above command:

	Update-DfsrConfigutationFromAD -Computer <all DCs>


###Lingering Objects

[Use Repadmin to remove lingering objects](https://technet.microsoft.com/en-us/library/cc785298%28v=WS.10%29.aspx)

[Remove Lingering Objects that cause AD Replication error 8606 and friends](http://blogs.technet.com/b/askds/archive/2014/09/15/remove-lingering-objects-that-cause-ad-replication-error-8606-and-friends.aspx)

	event id: AD Replication status: 8606, 8614, 8240,
	event id: Directory Service: 1988, 1388, 2042

[Lingering Object Liquidator](https://connect.microsoft.com/site1164/Downloads/DownloadDetails.aspx?DownloadID=54162)

Active Directory Utilities (Current Versions) [ReplDiag.exe]

	https://activedirectoryutils.codeplex.com/releases/view/13664


Windows Server 2008 and **later** DCs _will not work against Windows Server 2003 DCs_.

	ReplDiag /removelingeringobjects
	LDAP RemoveLingeringObjects rootDSE primative (most commonly executed using LDP.EXE or an LDIFDE import script)
	Repadmin /removelingeringobjects

[Clean that Active Directory forest of lingering objects](http://blogs.technet.com/b/glennl/archive/2007/07/26/clean-that-active-directory-forest-of-lingering-objects.aspx)

####Cleanup: Failed DC

[Remove a failed Domain Controller from a windows 2003 domain](https://community.spiceworks.com/how_to/616-remove-a-failed-domain-controller-from-a-windows-2003-domain)


##Virtualised Domain Controllers

[Running Domain Controllers in Hyper-V](https://technet.microsoft.com/en-us/library/d2cae85b-41ac-497f-8cd1-5fbaa6740ffe%28v=ws.10%29#backup_and_restore_considerations_for_virtualized_domain_controllers)

[Introduction to Active Directory Domain Services (AD DS) Virtualization (Level 100)](https://technet.microsoft.com/en-us/library/hh831734.aspx)

[Virtualized Domain Controller Technical Reference (Level 300)](https://technet.microsoft.com/en-us/library/jj574214.aspx)

Virtualisation: clone / snapshot / checkpoint

[Virtual Domain Controller Cloning in Windows Server 2012](http://blogs.technet.com/b/askpfeplat/archive/2012/10/01/virtual-domain-controller-cloning-in-windows-server-2012.aspx)

[What is the deal with Virtualization and Domain controllers?](http://blogs.technet.com/b/canitpro/archive/2013/06/06/what-s-the-deal-with-virtualization-and-domain-controllers.aspx)

>Before completing any transaction, AD DS first reads the value of the VM-Generation ID and compares it against the last value stored in the directory.
A mismatch is interpreted as a ‘rollback’ and the domain controller employs AD DS safeguards *new to Windows Server 2012*
comprised of resetting the InvocationID and discarding the RID pool.
>From this point forward, all transactions are associated with the domain controller’s new InvocationID.
Since other domain controllers do not recognize the new InvocationID, they will conclude that they have not already
seen these USNs and will accept the updates identified by the new InvocationID and USNs allowing the directory to converge.

###USN Rollback

[USN Rollback, Virtualized DCs and improvements on Windows Server 2012](http://blogs.technet.com/b/reference_point/archive/2012/12/10/usn-rollback-virtualized-dcs-and-improvements-on-windows-server-2012.aspx)

[How to detect and recover from a USN rollback in Windows Server 2003, Windows Server 2008, and Windows Server 2008 R2](https://support.microsoft.com/en-us/kb/875495)

###VM-Generation ID

> The VM-Generation ID feature allows hypervisor vendors to expose a virtual machine identifier that a Windows Server 2012
Domain Controller uses to detect the state of a virtual machine.

* All versions of Hyper-V that are Windows Server 2012/Windows 8 and later
* VMware vSphere 5.0 Update 2 (Both vCenter Server and ESXi must be at 5.0 Update 2)
* VMware vSphere 5.1 (ESXi must be at least 5.0 Update 2)
* VMware vSphere 5.5 and newer
* XenServer 6.2.0-70446 and later

[VM-Generation ID support in vSphere (2041872)](http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2041872)

[Hypervisor Support for VM-GenerationID](http://windowsitpro.com/hyper-v/hypervisor-support-vm-generationid)


##Time

["It's Simple!" - Time Configuration in Active Directory](http://blogs.technet.com/b/nepapfe/archive/2013/03/01/it-s-simple-time-configuration-in-active-directory.aspx)

In Kerberos V5, computers that are more than 5 minutes out of sync will not authenticate. Configurable by GPO:

* Computer Configuration\Windows Settings\Security Settings\Account Policies\Kerberos Policy
	* Maximum tolerance for computer clock synchronization

Active Directory won't work correctly if the clock is not synchronized around domain controllers/member machines. It uses time stamps to resolve replication conflicts.

[Synchronize the Time Server for the Domain Controller with an External Source](http://technet.microsoft.com/en-us/library/cc784553%28WS.10%29.aspx)

[Configuring Time Synchronization for all Computers in a Windows domain](http://www.altaro.com/hyper-v/configuring-time-synchronization-for-all-computers-in-windows-domain/)

[How to Get Hyper-V Time Synchronization Right](http://www.altaro.com/hyper-v/hyper-v-time-synchronization/) { Altaro blog - 2015-10-06}

[Configuring an Authoritative Time Server with Group Policy Using WMI Filtering](http://blogs.technet.com/b/askds/archive/2008/11/13/configuring-an-authoritative-time-server-with-group-policy-using-wmi-filtering.aspx)

	Select * from Win32_ComputerSystem where DomainRole = 5

To view the DomainRole value locally:

	wmic computersystem get domainrole

To view the DomainRole value remotely (where M1 is the remote computer):

	wmic /node:”M1” computersystem get domainrole

* 0 - Standalone Workstation
* 1 - Member Workstation
* 2 - Standalone Server
* 3 - Member Server
* 4 - DC
* 5 - PDCe

	event id: AD Replication status: 8606, 8614, 8240, 1988, 1388

[Restore Windows Time service on local computer to default settings](https://technet.microsoft.com/en-us/library/cc738995%28v=ws.10%29.aspx?f=255&MSPPError=-2147217396)

[Configure the Time Source for the Forest](https://technet.microsoft.com/en-us/library/cc794937%28v=ws.10%29.aspx)

I found a technique that uses a WMI filter in a GPO to apply the "get time from external source" instructions onto only the DC that has the PDC role.
That way, when you move the role, the NTP settings follow automatically.

[Time configuration in a Windows Domain](http://blogs.msmvps.com/mweber/2010/06/27/time-configuration-in-a-windows-domain/)

[Moving the NTP service to a new PDCe](https://dirteam.com/paul/2010/05/18/moving-the-ntp-service-to-a-new-pdce/)

to configure the Domain Controller with the PDC Emulator FSMO

	w32tm /config /manualpeerlist:PEERS /syncfromflags:manual /reliable:yes /update

to configure a domain computer for automatic domain time synchronization, run:

	w32tm /config /syncfromflags:domhier /update

	net stop w32time
	net start w32time

to reconfigure the previous PDC Emulator, in case of transferring/seizing the FSMO to another Domain Controller, run:

	w32tm /config /syncfromflags:domhier /reliable:no /update

	net stop w32time
	net start w32time

If you have to reconfigure a Windows 2000 Server Domain Controller, the steps are different
after transferring/seizing the PDC Emulator role to another Domain Controller:

	you have to modify the "Type" value to "Nt5Ds" without the quotes under this registry key:
	HKLM\ SYSTEM\ CurrentControlSet\ Services\ W32Time\ Parameters\

If you have problems with the time service configuration, then you can reset the time service to a default state the following way.

	net stop w32time
	w32tm /unregister
	w32tm /register
	net start w32time

[Fixing When Your Domain Traveled Back In Time, the Great System Time Rollback to the Year 2000](https://blogs.technet.microsoft.com/askpfeplat/2012/11/23/fixing-when-your-domain-traveled-back-in-time-the-great-system-time-rollback-to-the-year-2000/)


##Domain Rename

[How to Rename Your Active Directory Domain](http://blog.pluralsight.com/rename-active-directory-domain)

Rename / exchange / Split DNS / certs.
	https://community.spiceworks.com/topic/1225724-active-directory-after-a-merge-rename

[Simple Guide : How to Rename Domain Name in Windows Server 2012](https://mizitechinfo.wordpress.com/2013/06/10/simple-guide-how-to-rename-domain-name-in-windows-server-2012/)

Create the new Zone in DNS for the new name

Open an Admin cmd prompt.

	rendom /list

edit `DomainList.xml`, change: `DNSname` and `NetBiosName` in all sections in the file to the new Domain name (DNS & NetBios)

	rendom /showforest  # This is to show the potential changes; this step does not make any changes.
	remdom /upload      # Upload the rename instructions (Domainlist.xml) to the configuration directory partition on the DC holding the domain naming operations master role.
	rendom /prepare     # verify the readiness of each DC in the forest to carry out the rename instructions. Must contacts all DC’s successfully and return no errors.
	rendom /execute     # verifies readiness of all DC’s and then preforms the rename action on each one.

Once the process successful, your DC Server will be restarted. Once your DC Server restarted, log in **using the new Domain name** as administrator.

	gpfixup /olddns:adatum.com /newdns:cpx.local   # Refresh all intradomain references and links to group policy objects.
	gpfixup /oldnb:lon-dc1 /newnb:cpx
	rendom /clean       # Removes references of the old domain name from AD.
	rendom /end         # Unfreeze the forest configuration and allow further changes. Frozen during the rendom /upload step.

Join machines to new domain.

[How Domain Rename Works](https://technet.microsoft.com/en-us/library/cc738208%28WS.10%29.aspx) { 2014-11 }

[Domain Rename With or Without Exchange](http://blogs.msmvps.com/acefekay/2009/08/19/domain-rename-with-or-without-exchange/)


>The domain rename operation is not supported in Microsoft Exchange Server 2007 or Exchange Server 2010.
Domain Name System (DNS) domain rename is supported in Exchange Server 2003.

>However, renaming of the **NetBIOS** domain name is **not** supported in any version of Exchange Server. Other non-Microsoft applications might also not support domain rename.

https://support.microsoft.com/en-us/kb/925822

https://technet.microsoft.com/en-us/library/cc816631%28WS.10%29.aspx


##Forest Recovery

[Best Practices for Implementing Schema Updates or : How I Learned to Stop Worrying and Love the Forest Recovery](http://blogs.technet.com/b/askpfeplat/archive/2012/05/28/best-practices-for-implementing-schema-updates-or-how-i-learned-to-stop-worrying-and-love-the-forest-recovery.aspx)

[Planning for Active Directory Forest Recovery](https://technet.microsoft.com/en-us/library/planning-active-directory-forest-recovery%28v=WS.10%29.aspx)

[Disaster Recovery - A Reminder](https://blogs.technet.microsoft.com/askpfeplat/2015/09/21/disaster-recovery-a-reminder/)

[Reset Directory Services Restore Mode Password](http://www.top-password.com/knowledge/reset-directory-services-restore-mode-password.html) { DSRM }

	Ntdsutil
	reset password on server null|<servername>  # null is local system.
	# You'll be prompted twice to enter the new password.
	q  # to exit

[AD disaster recovery best practice?](https://community.spiceworks.com/topic/894315-windows-ad-disaster-recovery-best-practice)


##Functional Levels: Domain and Forest

[How to raise Active Directory domain and forest functional levels](https://support.microsoft.com/en-ie/kb/322692)
{ DFL/FFL }

[What is the Impact of Upgrading the Domain or Forest Functional Level?](http://blogs.technet.com/b/askds/archive/2011/06/14/what-is-the-impact-of-upgrading-the-domain-or-forest-functional-level.aspx)

[A few things you should know about raising the DFL and/or FFL to Windows Server 2008 R2](http://blogs.technet.com/b/askpfeplat/archive/2012/04/09/a-few-things-you-should-know-about-raising-the-dfl-and-or-ffl-to-windows-server-2008-r2.aspx)

###AD Upgrade/Migration:

[Upgrading or Migrating Active Directory to Windows Server 2012: - Build Your Roadmap Now](http://blogs.technet.com/b/askpfeplat/archive/2013/04/29/upgrading-or-migrating-active-directory-to-windows-server-2012-build-your-roadmap-now.aspx)

[Migrate Active Directory from Server 2003 to Server 2012 R2](https://community.spiceworks.com/how_to/57636-migrate-active-directory-from-server-2003-to-server-2012-r2)

[W2K3 to W2K8 and W2K8R2 Active Directory Upgrade Considerations](http://blogs.technet.com/b/glennl/archive/2009/08/21/w2k3-to-w2k8-active-directory-upgrade-considerations.aspx)

> When we DCPROMO a Domain Controller (DC) out of Active Directory (AD), it is a very easy wizard-driven process.
However, without proper forethought and a few precautions, that easy process can possibly have a far reaching
and substantial negative impact on production IT Operations.

First, Do No Harm: [Here are few items for a DC decommission checklist](http://blogs.technet.com/b/askpfeplat/archive/2012/08/06/first-do-no-harm.aspx)


Active Directory Risk Assessments – Lessons and Tips from the Field – Volume #1?
	http://blogs.technet.com/b/askpfeplat/archive/2015/06/29/active-directory-risk-assessments-lessons-and-tips-from-the-field-volume-1.aspx

[What is the Global Catalog](https://technet.microsoft.com/en-us/library/cc728188%28WS.10%29.aspx)


##Service Principal Names (SPN)

- A service principal name (SPN) is the name by which a client uniquely identifies an instance of a service.
- If you install multiple instances of a service on computers throughout a forest, each instance must have its own SPN.
- A given service instance can have multiple SPNs if there are multiple names that clients might use for authentication.

For example, an SPN always includes the name of the host computer on which the service instance is running, so a service instance
might register an SPN for each name or alias of its host.

From a **security perspective**, applications without properly registered [Service Principal Names](https://msdn.microsoft.com/en-us/library/ms677949%28v=vs.85%29.aspx)
may fall back to NTLM.


[Interesting findings on SETSPN -x -f](http://blogs.technet.com/b/askds/archive/2013/07/01/interesting-findings-on-setspn-x-f.aspx)

As we all know, the KDC’s cannot issue tickets for a particular service if there are duplicate SPN’s, and authentication does not work if the SPN is on the wrong account.

Experienced administrators learn to use the SETSPN utility to validate SPNs when authentication problems occur.
In the Windows Server 2008 version of SETSPN, we provide several options useful to identifying duplicate SPNs:

- If you want to look for a duplicate of a particular SPN: `SETSPN /q <SPN>`

- If you want to search for any duplicate in the domain: `SETSPN /x`

[Service Principal Name Attribute Limitations](http://blogs.technet.com/b/askpfeplat/archive/2014/09/01/service-principal-name-attribute-limitations.aspx)

[Kerberos errors in network captures](http://blogs.technet.com/b/askds/archive/2012/07/27/kerberos-errors-in-network-captures.aspx)

	[KDC_ERR_S_PRINCIPAL_UNKNOWN | KDC_ERR_C_PRINCIPAL_UNKNOWN | KDC_ERR_ETYPE_NOTSUPP | KDC_ERR_PREAUTH_REQUIRED | KDC_ERR_PREAUTH_FAILED |
	KRB_AP_ERR_SKEW | KRB_AP_ERR_REPEAT | KRB_AP_ERR_MODIFIED | KDC_ERR_BADOPTION | KDC_ERR_WRONG_REALM | KDC_ERR_TGT_REVOKED]

[The 411 on the KDC 11 Events](http://blogs.technet.com/b/askpfeplat/archive/2012/03/29/the-411-on-the-kdc-11-events.aspx)

[4771: Kerberos pre-authentication failed ](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4771)

[4768: A Kerberos authentication ticket (TGT) was requested](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4768)


##User Principal Name (UPN)

[What is UPN and why to use it?](https://apttech.wordpress.com/2012/02/29/what-is-upn-and-why-to-use-it/)

[HOW TO: Add UPN Suffixes to a Forest](http://support.microsoft.com/kb/243629) { This article has been archived. It is offered "as is" and will no longer be updated. }

[Add User Principal Name (UPN)) Suffixes](https://technet.microsoft.com/en-us/library/cc772007.aspx)

[Office 365 & Single Sign-On: How to Handle Different UserPrincipalName (UPN) Values](http://blogs.technet.com/b/askpfeplat/archive/2013/09/02/office-365-amp-single-sign-on-how-to-handle-different-userprincipalname-upn-values.aspx)

[Documenting Active Directory Infrastructure the Easy Way](http://blogs.technet.com/b/askds/archive/2007/10/12/documenting-active-directory-infrastructure-the-easy-way.aspx)



The DOs and DON’Ts of PKI – Microsoft ADCS
	http://kazmierczak.eu/itblog/2012/08/22/the-dos-and-donts-of-pki-microsoft-adcs/


<hr>

##AD - InDepth

> Many links to take you from starting with AD to probably excessive knowledge.

[Active Directory Domain Services Overview](https://technet.microsoft.com/en-us/library/hh831484.aspx)

[Everything you need to get started with Active Directory](http://blogs.technet.com/b/ashleymcglone/archive/2012/01/03/everything-you-need-to-get-started-with-active-directory.aspx)  { Ashley McGlone Blog }

[MCM: So You Want to Be a Active Directory Master](http://blogs.technet.com/b/askpfeplat/archive/2012/05/21/so-you-want-to-be-a-master-eh.aspx)

[MCM: Core Active Directory Internals](http://blogs.technet.com/b/askpfeplat/archive/2012/07/23/mcm-core-active-directory-internals.aspx

[MCM: Active Directory Indexing For the Masses](http://blogs.technet.com/b/askpfeplat/archive/2012/11/11/mcm-active-directory-indexing-for-the-masses.aspx)

[How the Active Directory Replication Model Works](https://technet.microsoft.com/en-us/library/cc772726%28WS.10%29.aspx)

Ask the Directory Services Team Blog - Further reading around how you can amp up your Active Directory skills:

[Post-Graduate AD Studies](http://blogs.technet.com/b/askds/archive/2010/07/27/post-graduate-ad-studies.aspx)

[Active Directory Maximum Limits - Scalability](https://technet.microsoft.com/en-us/library/active-directory-maximum-limits-scalability%28v=ws.10%29.aspx)

<hr>

## Things to try and script

### Script these - instead of leaving them as manual checks

####Verify AD Schema Version:

	Windows 2000 Server			13
	Windows 2000 + Exch 2000	17
	Windows 2003 RTM, SP1, SP2	30
	Windows 2003 R2				31
	Windows 2008				44
	Windows 2008 R2				47
	Windows Server 2012 Beta	52
	Windows Server 2012			56
	Windows Server 2012 R2		69

[How to Query Active Directory to Determine the Schema Version](http://blogs.msdn.com/b/muaddib/archive/2012/07/03/determine-active-directory-schema-version.aspx)

	Get-ADObject (get-adrootdse).schemaNamingContext -Property objectVersion
	-or-
	dsquery * cn=schema,cn=configuration,dc=domainname,dc=local -scope base -attr objectVersion
		Replace “dc=domainname” with your information:

####Tombstone lifetime

http://learn-powershell.net/2013/07/28/quick-hits-determine-tombstone-lifetime-in-active-directory/

	(get-adobject "cn=Directory Service,cn=Windows NT,cn=Services,cn=Configuration,dc=rivendell,dc=com" -properties "tombstonelifetime").tombstonelifetime

[Determine the tombstone lifetime for the forest](https://technet.microsoft.com/en-us/library/cc784932%28v=ws.10%29.aspx?f=255&MSPPError=-2147217396)

	dsquery * "cn=directory service,cn=windows nt,cn=services,cn=configuration,dc=<forestDN>" –scope base –attr tombstonelifetime


####How do you know if all your domain controllers have been upgraded and have replicated afterwards? Two commands are helpful here:

	repadmin /replsum will give you summary information you can utilize, and
	repadmin /showrepl will tell you if the schema partition has replicated.

Plus you can check the schema version numbers; open Registry Editor and navigate to the Schema Version registry subkey found under

	HKLM\System\CurrentControlSet\Services\NTDS\Parameters

Check Active Directory Forest Schema Version for Windows Server 2012.
The `ADPrep /ForestPrep` command will set a value for ObjectVersion attribute on Schema partition.
Once Active Directory Forest schema is extended by using ADPrep /ForestPrep command, a preliminary check must be performed to make schema has been extended.

Please follow the steps to check the value of objectVersion attribute:

- Run LDP.exe, go to Connection and then click on Bind.
- Click Ok. Next click on View, Tree and then select the following LDAP path from the dropdown list: CN=Schema,CN=Configuration,DC=<DomainName>,DC=<Com>
- Click Ok to run the LDP query against the above LDAP Path.
- In Right Pane, check objectVersion: 56 attribute. If it is 56 Admin ADPrep command successfully extended the schema


http://www.windowsnetworking.com/kbase/WindowsTips/WindowsServer2008/AdminTips/ActiveDirectory/AQuickTiptomakesureAdprepForestPrepforWindowsServer2008hasrunsuccessfully.html

http://www.windowsnetworking.com/kbase/WindowsTips/Windows2003/AdminTips/Migration/VerifyingAdprep.html

http://www.windowsnetworking.com/kbase/WindowsTips/WindowsServer2012/AdminTips/ActiveDirectory/quick-tip-check-active-directory-schema-version-windows-server-2012.html


####Determining Whether a Security Principal Is Protected by **AdminSDHolder**

> The AdminSDHolder is an important security feature in Active Directory.
The AdminSDHolder, protected groups and Security Descriptor propagator help secure user accounts that contain elevated Active Directory permissions.

The AdminSDHolder functionality has evolved from Windows 2000 Server to Windows Server 2008. During this evolution,
Microsoft has expanded the number of objects that are secured by AdminSDHolder, introduced the ability to exclude certain
groups from the AdminSDHolder and added the ability to control how often AdminSDHolder runs.

[AdminSDHolder, Protected Groups and SDPROP](https://technet.microsoft.com/en-us/magazine/2009.09.sdadminholder.aspx)

* To find all user objects in a domain that are protected by AdminSDHolder, type:

	Adfind.exe -b DC=domain,DC=com -f "&(objectcategory=person)(samaccountname=*)(admincount=1)" -dn

* To find all groups in a domain that are protected by AdminSDHolder, type:

	Adfind.exe -b DC=domain,DC=com -f "&(objectcategory=group)(admincount=1)" -dn


####How to force an authoritative and non-authoritative synchronization for DFSR-replicated SYSVOL

https://support.microsoft.com/en-us/kb/2218556

Can the AD settings be changed with get-ADObject and set-ADObject:

####Perform a non-authoritative synchronization of DFSR-replicated SYSVOL (like "D2" for FRS)

Modify the following distinguished name (DN) value and attribute on each of the domain controllers that you want to make non-authoritative:

	CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=<the server name>,OU=Domain Controllers,DC=<domain>
	msDFSR-Enabled=FALSE

<more info, see url above>

####Perform an authoritative synchronization of DFSR-replicated SYSVOL (like "D4" for FRS)

Modify the following DN and two attributes on the domain controller you want to make authoritative (preferrably the PDC Emulator,
which is usually the most up to date for SYSVOL contents):

	CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=<the server name>,OU=Domain Controllers,DC=<domain>
		msDFSR-Enabled=FALSE
		msDFSR-options=1

Modify the following DN and single attribute on all other domain controllers in that domain:

	CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=<each other server name>,OU=Domain Controllers,DC=<domain>
		msDFSR-Enabled=FALSE

<more info, see url above>


##AD Issues that need to be addressed:

Issues with monitoring replication are addressed above.

http://community.spiceworks.com/topic/1150455-what-issues-are-there-with-ad-windows-that-need-to-be-manually-fixed

###Hardening Group Policy

MS15-011: Vulnerability in Group Policy could allow remote code execution: February 10, 2015

	https://support.microsoft.com/en-us/kb/3000483
	http://community.spiceworks.com/topic/787725-jasbug-group-policy-fix

MS15-014: Vulnerability in Group Policy could allow security feature bypass: February 10, 2015

	https://support.microsoft.com/en-ie/kb/3004361
	https://technet.microsoft.com/en-us/library/security/ms15-014

[Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx)

[MS15-011 & MS15-014: Hardening Group Policy](http://blogs.technet.com/b/srd/archive/2015/02/10/ms15-011-amp-ms15-014-hardening-group-policy.aspx)


MS14-025 - Important - Vulnerability in Group Policy Preferences Could Allow Elevation of Privilege (2962486)

	https://technet.microsoft.com/library/security/ms14-025

	https://support.microsoft.com/en-us/kb/2962486

	https://sdmsoftware.com/group-policy-blog/security-related/remediating-group-policy-preference-passwords/

	PasswordRoll script: /av/z/PS/AD/Invoke-LocalPasswordRoll.ps1 [Deprecated, use LAPS, see below]
	GPP scan for Cpassword script: /av/z/PS/AD/Get-SettingsWithCPassword.ps1 [Deprecated by the SDM software tool below]

###Local Administrator Password Solution (LAPS)

[LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899)

community.spiceworks.com/topic/932571-manage-and-randomize-your-local-admin-account-passwords-via-ad-and-laps

[Remediating Group Policy Preference Passwords](https://sdmsoftware.com/group-policy-blog/security-related/remediating-group-policy-preference-passwords/)

SDM Software - [Group Policy Preference Password Remediation Utility (freeware)](https://sdmsoftware.com/group-policy-management-products/freeware-group-policy-tools-utilities/)

[Local Administrator Password Solution (LAPS) Implementation Hints and Security Nerd Commentary (including mini threat model)](http://blogs.technet.com/b/askpfeplat/archive/2015/12/28/local-administrator-password-solution-laps-implementation-hints-and-security-nerd-commentary-including-mini-threat-model.aspx)

>Credential theft is a major problem in the security landscape today. Matching local administrator passwords in an environment
often contribute to that problem and are a popular target for bad guys. Far more than zero days or malware, credentials are
what allow attackers to be successful in your network.

Active Directory Troubleshooting
	http://www.deuby.com/active-directory-troubleshooting/

[Reset Local Administrator Password Using A Different Random String On Each Computer And Recover The Passwords Securely](https://cyber-defense.sans.org/blog/2013/08/01/reset-local-administrator-password-automatically-with-a-different-password-across-the-enterprise) { LAPS alternative }


###Active Directory Health Checks for Domain Controllers

[Active Directory Health Checks for Domain Controllers](http://blogs.msmvps.com/ad/blog/2008/06/04/active-directory-health-checks-for-domain-controllers/)

- The Event Viewer is always a must.
	- I look at all the logs before and after the update to the domain controller looking for abnormal events.
	- With the pre-check I usually go back a month of logs to get more historical data. I then run through a couple
	of command line utilities.  One thing I always do is pipe my commands out to a text document.

This is a must and will always tell you if there is trouble with your DCs and/or services associated with it

	Dcdiag.exe /v >> c:temppre_dcdiag.txt

This will let me know if there are issues with the networking components on the DC.
This along with the post test also is a quick easy way to ensure the patch I just installed is really installed (just check the top of the log)

	Netdiag.exe /v >> c:temppre_Netdiag.txt

I've felt the pain of a DHCP server somehow not being authorized after a patch.  This allows me verify the server count and names.

	Netsh dhcp show server >> c:temppre_dhcp.txt

This shows all my replication and if it was successful or not.  GCs will have more info here than a normal DC.

	Repadmin /showreps >> c:temppre_rep_partners.txt

This is the one that always takes forever but will let you know who you are having issues replicating with.

	repadmin /replsum /errorsonly >> c:temppre_repadmin_err.txt

After I run and check the pre_ scripts I update my server.  When it is done I run post_ scripts which are the same thing
but this allows me to verify them against the scripts earlier.

#####Query FSMO role holders:

	netdom query fsmo

#####Query DNS to see if old DC still lingers:

Open a Command Prompt

	nslookup [ENTER]
	set type=all [ENTER]
	_ldap._tcp.dc._msdcs.<Domain_Name>  [ENTER]

where <Domain_Name> is the name of your domain

###Metadata Cleanup

[Clean Up Server Metadata](https://technet.microsoft.com/en-us/library/cc816907%28v=ws.10%29.aspx)

> Metadata cleanup is a required procedure after a forced removal of Active Directory Domain Services (AD DS).
> You perform metadata cleanup on a domain controller in the domain of the domain controller that you forcibly removed.

* Metadata cleanup removes data from AD DS that identifies a domain controller to the replication system.
* Metadata cleanup also removes File Replication Service (FRS) and Distributed File System (DFS) Replication connections
and attempts to transfer or seize any operations master (also known as flexible single master operations or FSMO) roles that the retired domain controller holds.

[Metadata cleanup over GUI](http://kpytko.pl/active-directory-domain-services/metadata-cleanup-over-gui/)

[Finding Orphaned Domain Controllers in Active Directory Sites and Services](https://blogs.technet.microsoft.com/askpfeplat/2016/03/07/finding-orphaned-domain-controllers-in-active-directory-sites-and-services-2/)

[How to remove data in Active Directory after an unsuccessful domain controller demotion](https://support.microsoft.com/en-us/kb/216498)

http://www.wisesoft.co.uk/scripts/active_directory/powershell.aspx

[Scripting when a user last logged on](https://community.spiceworks.com/topic/1440807-script-lastlogontimestamp-export-csv)

`LastLogonTimeStamp` is saved whenever a user logs in and the date of their login is 14 days older then the LAST LastLogonTimeStamp.  If it's less then nothing is updated.
The purpose of the field is to spot User and Computer objects that are old and unused (say 30 days).

`LastLogon` is the only field that has when the user last logged in and it's only on the domain controller where the user authenticated to.

`LastLogonDate` is replicated and can have that information, but it's on a very slow replication cycle (as long as 11 days in larger environments).
If you're smaller this is the field to go with, but in large environments, especially with a lot of separate sites, it's too unreliable for most reports.


Replicate the contents of 1 DC AD to another

	repadmin /replicate <target_DC> <source_DC>  "cd=example,dc=com"

Show info about the replication config assciated with a DC.

	repadmin /showrepl

Initiate recalculation of the KCC's inbound replication topography

	repadmin /kcc

What users have their passwords stored on an RODC:

	repadmin /prp view <rodc_DC> reveal

DFS Replication diagnostics:

	dfsdiag /?
	dfsdiag /testdcs  # Tests DCs and DFS for DCs.

Determine whether or not you can talk to AD and locate a DC:

	nltest /dsgetdc?example.com   # Are you talking with a DC on that domain?
	nltest /sc_query:example.com  # Do you have a secure channel to that location?

	nltest /domain_trusts /all_trusts /v  # What odes this do? Shows the Domain GUID.

Active Directory Change Notification:

Speed up replication of AD changes. Using ADSIEdit.

	adsiedit.msc / Connect to: Naming Context {configuration}
	Config / Config / CN=Sites / CN = Inter-Site Transports / CN-IP : {site link objects}
	properties of site-link object: options = 1 {USE_NOTIFY}


##Delegation:

[Delegate Add/Delete Computer Objects in AD](http://sigkillit.com/2013/06/12/delegate-adddelete-computer-objects-in-ad/)

Redirect the Default Computer Container to the New Computer OU in AD - [Redircmp.exe](http://support.microsoft.com/kb/324949).
On your AD Domain Controller, run the following command:

	redircmp.exe  DC=contoso,DC=local with your domain name):

[Redirecting the users and computers containers in Active Directory domains](https://support.microsoft.com/en-ie/kb/324949)


##Recovery

[Restore Default Permissions on Active Directory Organizational Units {OU}](http://social.technet.microsoft.com/wiki/contents/articles/18726.restore-default-permissions-on-active-directory-organizational-units-ou.aspx)

>The question is, how can easily restore default permissions on OU?
Here is soloution. I create a new OU, called DefaultOUPermissions.

Open PowerShell as Administrator. Change drive to AD drive or location.

	Import-Module ActiveDiretory
	Set-Location AD:

Take a sample of the default permissions, such as ACEs, Owner, etc (my sample OU name is DefaultOUPermissions and domain name is Contoso.com):

	$OUDefaultAcl = (Get-Acl "AD:OU=DefaultOUPermissions,DC=Contoso,DC=Com")

Restore MCA permission to default:

	Set-Acl "AD:OU=MCA,DC=Contoso,DC=Com" -AclObject $OUDefaultAcl

[Returning to a Domain's Default Permissions](http://windowsitpro.com/windows-server/returning-domains-default-permissions)

Dsacls lets you configure AD permissions from the command line.

	dsacls DC=Acme,DC=Com /S /T

would reset the permissions for the acme.com domain.

	/S - resets the specified object's permissions to the default ACL specified in AD's schema.
	/T - causes Dsacls to reset permissions for all the specified object's child objects.


###Version Store

[The Version Store Called, and They're All Out of Buckets](https://blogs.technet.microsoft.com/askds/2016/06/14/the-version-store-called-and-theyre-all-out-of-buckets/)

####Error messages

	Log Name: Directory Service
	Source:   Microsoft-Windows-ActiveDirectory_DomainService
	Date:
	Event ID: 1519
	Task Category: Internal Processing
	Level: Error
	Keywords: Classic
	User: S-1-5-21-4276753195-2149800008-4148487879-500
	Computer: DC01.contoso.com
	Description:
	Internal Error: Active Directory Domain Services could not perform an operation because the database has run out of version storage.

	And also:

	Log Name: Directory Service
	Source:   NTDS ISAM
	Date:
	Event ID: 623
	Task Category: (14)
	Level:    Error
	Keywords: Classic
	User:     N/A
	Computer: DC01.contoso.com
	Description:
	NTDS (480) NTDSA: The version store for this instance (0) has reached its maximum size of 408Mb.
	It is likely that a long-running transaction is preventing cleanup of the version store and causing it to build up in size.
	Updates will be rejected until the long-running transaction has been completely committed or rolled back.



##Privileges / Rights

To see your privileges:

	whoami /priv

[Privileges](https://technet.microsoft.com/en-us/library/cc740217%28v=ws.10%29.aspx)

[User Rights Assignment](https://technet.microsoft.com/en-us/library/cc780182%28v=ws.10%29.aspx)

[PowerShell: Granting Computer Join Permissions](http://windowsitpro.com/windows-server/powershell-granting-computer-join-permissions)

>By default, domain users can create and join up to 10 computers to the domain.
You can change this value in a domain by modifying the `ms-DS-MachineAccountQuota` attribute. KB: [Default limit to number of workstations a user can join to the domain](https://support.microsoft.com/en-us/kb/243327)

* [Security Identifiers Technical Overview](https://technet.microsoft.com/en-us/library/dn743661.aspx) {SID}
* [Security Principals Technical Overview](https://technet.microsoft.com/en-us/library/dn486814(v=ws.11).aspx)
	* [Special Identities](https://technet.microsoft.com/en-us/library/dn617202(v=ws.11).aspx#BKMK_PrincipalSelf)


