module SimpleAddrScanTuning;
export {
	## Put hosts you want to ignore scans from into this table.
	const exceptions: table[addr] of set[port] &redef;
}

hook Scan::addr_scan_policy(scanner: addr, victim: addr, scanned_port: port)
	{
	if ( scanner in exceptions && scanned_port in exceptions[scanner] )
		break;
	}
