# Lab query examples

The [synthetic event dataset](../evidence/events.csv) is a readable timeline summary, not raw telemetry. The examples below demonstrate investigation pivots against a lab table populated from that CSV. They do not prove that a real incident occurred or that data was stolen.

## Microsoft Sentinel / Kusto

Assume the CSV has been imported into a lab table named IncidentEvents with the same lowercase column names.

### Correlate the phishing link with the later sign-in

~~~kusto
IncidentEvents
| where case_id == "INC-01"
| where event_type in ("url_redirect", "browser_navigation", "successful_signin", "session_issued")
| project time_utc, source, asset, identity, source_ip, destination, event_type, observation, assessment
| order by time_utc asc
~~~

### Review the ransomware-like activity sequence

~~~kusto
IncidentEvents
| where case_id == "INC-02"
| where event_type in ("powershell_process_start", "encoded_command_child_process", "file_rename_write_burst", "similar_file_activity", "abnormal_write_volume")
| project time_utc, source, asset, event_type, observation, assessment
| order by time_utc asc
~~~

### Inspect the network egress sequence

~~~kusto
IncidentEvents
| where case_id == "INC-03"
| where event_type in ("dns_query", "outbound_connection", "repeated_outbound_sessions", "egress_volume_anomaly", "proxy_request")
| project time_utc, source, asset, source_ip, destination, event_type, observation, assessment
| order by time_utc asc
~~~

## Splunk lookup example

After importing events.csv as a lookup named incident_events.csv:

~~~spl
| inputlookup incident_events.csv
| search case_id="INC-03"
| search event_type IN ("dns_query", "outbound_connection", "repeated_outbound_sessions", "egress_volume_anomaly", "proxy_request")
| table time_utc source asset source_ip destination event_type observation assessment
| sort 0 time_utc
~~~

The sample times are time-of-day strings, so the queries are for sequence review within a case. They do not support cross-day correlation or actual time-window detection without a real dataset and date field.
