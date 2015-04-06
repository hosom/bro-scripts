@load base/frameworks/notice
@load base/frameworks/sumstats/plugins/variance.bro

module DetectICMPSHell;

export {
	redef enum Notice::Type += {
		## High variance in ICMP connections indicates ICMP shells
		ICMP_High_Variance
	};

	## Tolerance level for variance of ICMP connections from the 
	## same client
	const icmp_variance_threshold = 1.0 &redef;
}

event icmp_sent(c: connection, icmp: icmp_conn)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=|payload|]);
	}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=|payload|]);
	}

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="icmp.shell.variance",
								 $apply=set(SumStats::VARIANCE));

	SumStats::create([$name="detect-icmp-shell",
					  $epoch=5mins,
					  $reducers=set(r1),
					  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
					  	{
					  	return result["icmp.shell.variance"]$variance;
					  	},
					  $threshold=icmp_variance_threshold,
					  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
					  	{
					  	NOTICE([$note=ICMP_High_Variance,
					  			$src=key$host,
					  			$msg="Observed high ICMP orig_bytes variance.",
					  			$sub="May indicate an ICMP Shell.",
					  			$identifier=cat(key$host)]);
					  	}]);
	}
