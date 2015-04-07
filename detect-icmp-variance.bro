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

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
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
