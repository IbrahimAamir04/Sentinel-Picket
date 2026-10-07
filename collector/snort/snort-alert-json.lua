-- Add to your snort.lua (or include it) so Snort 3 writes one JSON alert per line for the collector.
--
-- IMPORTANT: confirm these field names against YOUR Snort build before relying on them:
--     snort --help-module alert_json
-- This repository could not be tested against a live Snort 3. The field list below follows the alert_json
-- documentation; if your build rejects a name, remove it. The collector tolerates any of them being absent.

alert_json =
{
    file = true,        -- write to a file in the Snort log directory (-l), usually alert_json.txt
    limit = 100,        -- rotate after this many MB so the file cannot grow without bound

    -- src_addr/src_port/dst_addr/dst_port avoid parsing "address:port" strings (safer for IPv6).
    -- seconds gives an unambiguous epoch time (the text timestamp has no year or time zone).
    -- b64_data is only needed if you enable [payloads] in the collector, and it makes the file larger.
    fields = 'seconds timestamp pkt_num proto dir src_addr src_port dst_addr dst_port rule msg class priority action b64_data',
}
