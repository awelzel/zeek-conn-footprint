# zeek-conn-footprint

Record long running connections with a large footprint in ``conn_footprint.log``.

This can aid in finding per-connection state growth, but does come with a
certain runtime overhead due to the usage of ``val_footprint()``.

## Installation

    zkg install https://github.com/awelzel/zeek-conn-footprint.git

## Example log

```
{
  "ts": 1687514059.546506,
  "start_time": 1687513335.154572,
  "uid": "CRwAQ83P7xzkhv6iBc",
  "history": "ShAdD",
  "id.orig_h": "172.17.0.1",
  "id.orig_p": 57386,
  "id.resp_h": "172.17.0.2",
  "id.resp_p": 445,
  "duration": 724.3919339179993,
  "total_size": 675932369,
  "total_packets": 3400106,
  "total_bytes_ip": 3400106,
  "footprint": 6937177,
  "service": [
    "NTLM",
    "DCE_RPC",
    "SMB"
  ],
  "details": "dce_rpc_backing=6936805 {entries 199975}, service_violation=0, ntlm=27 {domainname=1, id=8, username=1, done=1, uid=1, hostname=1, server_nb_computer_name=1, server_dns_computer_name=1, ts=1}, uid=1, history=1, resp=12 {size=1, state=1, num_bytes_ip=1, l2_addr=1, num_pkts=1, flow_label=1}, service=9 {entries 3}, extract_resp=1, ftp_data_reuse=1, start_time=1, removal_hooks=6 {entries 2}, smb_state=231 {tid_map=22 {entries 1}, current_cmd=76, fid_map=0, pending_cmds=79 {entries 1}, pipe_map=0, recent_files=0, current_tree=19, current_file=27}, duration=1, orig=12 {size=1, state=1, num_bytes_ip=1, l2_addr=1, num_pkts=1, flow_label=1}, id=8 {orig_h=1, resp_p=1, resp_h=1, orig_p=1}, dce_rpc_state=9 {named_pipe=1, ctx_to_uuid=4 {entries 1}, uuid=1}, extract_orig=1"
}
```

## Configuration options

```
ConnFootprint::conn_create_expire: interval = 12hr;
ConnFootprint::min_duration          = 1min;
ConnFootprint::min_footprint         = 10000;
ConnFootprint::min_footprint_details = 20000;
ConnFootprint::report_interval       = 1min;
```
