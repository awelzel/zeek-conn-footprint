## Script that logs footprints of all connections with durations longer
## than min_duration. Log entries are only produced if footprint exceeds
## min_footprint.
module ConnFootprint;

export {
	option conn_create_expire: interval = 12hr;
	option min_duration          = 2min;
	option min_footprint         = 10000;
	option min_footprint_details = 20000;
	option report_interval       = 1min;

	redef enum Log::ID += {
		LOG,
	};

	type Info: record {
		ts:             time &log &default=network_time();
		start_time:     time &log;
		uid:            string &log;
		id:             conn_id &log;
		duration:       interval &log;
		total_size:     count &log;
		total_packets:  count &log;
		total_bytes_ip: count &log;
		footprint:      count &log;
		service:        set[string] &log;
		details:        string &log &optional;
	};
}


# Tracking all active connections.
global active_connections: set[conn_id] &create_expire=conn_create_expire;

event new_connection(c: connection) {
	add active_connections[c$id];
}

event connection_state_remove(c: connection) {
	delete active_connections[c$id];
}

function record_details(r: any, recurse: count &default=0): string {
	local parts: vector of string = vector();
	for ( f, field in record_fields(r) ) {
		if ( field?$value ) {
			local vfp = val_footprint(field$value);
			local part = fmt("%s=%d", cat(f), vfp);
			if ( vfp > 0 ) {  # Add some details if we can.
				if (field$type_name == /^table\[.*\] of .*/ || field$type_name == /^set\[.+\].*/)
					part = fmt("%s {entries %d}", part, |field$value|);
				else if ( field$type_name == /^record .*/ && recurse > 0) {
					part = fmt("%s {%s}", part, record_details(field$value, recurse - 1));
				}
			}
			parts += part;
			}
	}

	return join_string_vec(parts, ", ");
}

event ConnFootprint::log() {
	local now = network_time();

	for ( cid in active_connections ) {
		if ( ! connection_exists(cid) )
			next;

		local c = lookup_connection(cid);
		local duration = now - c$start_time;

		if ( duration < min_duration )
			next;

		local c_footprint = val_footprint(c);

		if ( c_footprint < min_footprint )
			next;

		local total_packets = 0;
		if ( c$orig?$num_pkts )
			total_packets += c$orig$num_pkts;
		if ( c$resp?$num_pkts )
			total_packets += c$resp$num_pkts;

		local total_bytes_ip = 0;
		if ( c$orig?$num_pkts )
			total_bytes_ip += c$orig$num_pkts;
		if ( c$resp?$num_pkts )
			total_bytes_ip += c$resp$num_pkts;

		local rec = Info(
			$start_time=c$start_time,
			$uid=c$uid,
			$id=cid,
			$duration=duration,
			$total_size=c$orig$size + c$resp$size,
			$total_packets=total_packets,
			$total_bytes_ip=total_bytes_ip,
			$footprint=c_footprint,
			$service=c$service
		);

		if ( c_footprint > min_footprint_details )
			rec$details = record_details(c, 1);

		Log::write(LOG, rec);
	}

	schedule report_interval { ConnFootprint::log() };
}

event zeek_init() {
	Log::create_stream(LOG, [$columns=Info, $path="conn_footprint"]);
	schedule report_interval { ConnFootprint::log() };
}
