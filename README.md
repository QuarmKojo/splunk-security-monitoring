# Splunk Security Monitoring

Hands-on SIEM project in Splunk Enterprise 9.4: searches, alerts, reports, and dashboards built on **Apache web server logs** and **Windows Server logs**, with a focus on spotting abnormal activity using baselines and thresholds.

## Contents

- [Environment and datasets](#environment-and-datasets)
- [Method: baseline and threshold detection](#method-baseline-and-threshold-detection)
- [1. Apache web log analysis](#1-apache-web-log-analysis)
- [2. Reports: speed test and Nessus](#2-reports-speed-test-and-nessus)
- [3. Windows Server attack log analysis](#3-windows-server-attack-log-analysis)
- [4. Alerts](#4-alerts)
- [5. Dashboards](#5-dashboards)
- [Key findings](#key-findings)
- [Build process (dashboard edit mode)](#build-process-dashboard-edit-mode)

## Environment and datasets

- Splunk Enterprise 9.4 running in a virtual lab (Kali/Linux workstation, Splunk on localhost:8000)
- Search app: SPL searches, saved searches, scheduled alerts, reports, and Simple XML dashboards

| Dataset | Source | Used for |
|---|---|---|
| `apache_logs.txt` | Apache access logs (`access_combined`) | Geo-location, traffic baselines, user agents, server errors |
| `apache_attack_logs.txt` | Apache access logs during an attack window | HTTP methods, response codes, POST alerting |
| `windows_server_attack_logs.csv` | Windows Server event logs | Severity, success/failure, per-hour thresholds, signatures, users |
| `server_speedtest.csv` | Server speed test results | Upload/download ratio report |
| `nessus_logs.csv` | Nessus vulnerability scan output | Critical findings per host |

## Method: baseline and threshold detection

Alert thresholds are not guesses. Each is derived from the data:

1. Bin events into one-hour buckets (`bin _time span=1h`)
2. Count events per bucket (`stats count by _time`)
3. Compute the mean and standard deviation (`stats avg`, `stdev` or `eventstats`)
4. Set the threshold at **mean + 2 × standard deviation** and keep only the buckets that exceed it (`where count > threshold`)

## 1. Apache web log analysis

### Where is the traffic coming from?

`iplocation` enriches each client IP with a country. The United States is the largest share of requests.

![Top countries by request count](screenshots/499-apache-top-countries-pie.png)

### Baseline for non-US traffic

Hourly non-US request counts have an average of about 73.1 and a standard deviation of about 22.8, which gives a threshold of about 119 requests per hour.

![Hourly non-US average and standard deviation](screenshots/500-apache-non-us-hourly-avg-stdev.png)

### Spike above the threshold

One hour (2020-03-20 00:00) exceeds the threshold with 120 non-US requests.

![Non-US traffic above threshold](screenshots/502-apache-non-us-threshold-spike.png)

The same search is then saved as an alert (**Save As**).

![Saving the spike search as an alert](screenshots/503-apache-spike-save-as-alert.png)

### Who is making the requests?

Top 20 user agents. Chrome on Windows leads, and crawlers such as Googlebot and archive.org also appear.

![Top 20 user agents](screenshots/505-apache-top-useragents-pie.png)

### Server errors

Radial gauge counting HTTP 5xx responses (`status>=500`): 3 server errors.

![Server error gauge](screenshots/506-apache-server-errors-gauge.png)

### Attack log: methods and response codes

In `apache_attack_logs.txt` (4,497 events), GET is 70.2% of requests, POST is 29.4%, and HEAD and OPTIONS are negligible.

![HTTP methods](screenshots/528-apache-attack-http-methods.png)

200 responses are 83.3% (3,746) of events, with a small share of 301, 304, and 404.

![HTTP response codes](screenshots/530-apache-attack-http-response-codes.png)

### POST requests per hour

POST requests above 3 per hour appear in two hours: 2020-03-18 16:00 (4) and 2020-03-20 13:00 (7).

![POST requests per hour](screenshots/531-apache-posts-per-hour-search.png)

## 2. Reports: speed test and Nessus

### Server speed test

A calculated field, `upload_download_ratio = UPLOAD_MEGABITS / DOWNLOAD_MEGABITS`, across 23 events.

![Upload/download ratio search](screenshots/507-speedtest-upload-download-ratio.png)

Saved as the **Server Speed Test** report.

![Saved Server Speed Test report](screenshots/508-speedtest-saved-report.png)

### Nessus findings for one host

All 49 events for host 10.11.36.23 are **critical** severity (100%).

![Critical Nessus findings](screenshots/509-nessus-critical-vulns-host.png)

## 3. Windows Server attack log analysis

5,949 events analyzed from `windows_server_attack_logs.csv`.

### Severity levels

Informational events are 4,383 (79.8%) and high-severity events are 1,111 (20.2%).

![Severity levels](screenshots/510-windows-severity-levels.png)

### Success versus failure

5,856 successes (98.4%) against 93 failures (1.6%).

![Success vs failure](screenshots/512-windows-success-vs-failure.png)

### Failed events per hour, with a threshold

The threshold is the average (about 8.5) plus two standard deviations (about 9.1), which is about 26.6. The hour of 2020-03-25 08:00 is flagged with 35 failures.

![Failed events by hour](screenshots/513-windows-failed-events-by-hour-threshold.png)

### Other thresholds tested

Successful logons (event ID 4624 above 19 per hour) and account deletions (event ID 4726 above 21 per hour) returned no results, meaning no hour exceeded those baselines.

![Successful logons, event ID 4624](screenshots/516-windows-successful-logons-4624-no-results.png)

![Account deletions, event ID 4726](screenshots/517-windows-account-deletions-4726-no-results.png)

## 4. Alerts

Both alerts are scheduled hourly, trigger when the number of results is greater than 0, and send an email. Neither has fired yet.

**`Posts_per_Hour`**

![Posts_per_Hour alert](screenshots/504-alert-posts-per-hour-config.png)

**`Failed Events By Hour`**

![Failed Events By Hour alert](screenshots/515-alert-failed-events-by-hour-config.png)

## 5. Dashboards

### Windows Server Monitoring

Panels: Signatures Per Hour, Users per Hour, Signature Count, User Count, and Accounts Created, with a time-range filter.

![Windows Server Monitoring, top panels](screenshots/523-windows-dashboard-top-panels.png)

![Signature Count and User Count pies](screenshots/522-windows-dashboard-signature-user-count.png)

![Accounts Created gauge](screenshots/521-windows-dashboard-accounts-created-gauge.png)

#### Baseline day versus attack day

On the baseline day (Mar 24), signatures stay between about 50 and 100 per hour and user activity is flat.

![Mar 24 baseline](screenshots/551-windows-dashboard-baseline-day.png)

On Mar 25 there are two sharp spikes.

![Mar 25 attack day](screenshots/550-windows-dashboard-attack-day-spikes.png)

At 2:00 AM there are 896 account lockouts in a single hour.

![Account lockout spike](screenshots/545-windows-account-lockout-spike-tooltip.png)

At 9:00 AM there are 1,258 password reset attempts in a single hour.

![Password reset spike](screenshots/544-windows-password-reset-spike-tooltip.png)

The signature tables show the same shift. On the baseline day, event types are spread evenly (about 6.5 to 7.2% each).

![Baseline signature table](screenshots/542-windows-dashboard-signature-table-baseline.png)

On the attack day, password reset attempts are 2,128 (35.8%) and lockouts are 1,811 (30.4%). `user_k` and `user_a` dominate the User Count.

![Attack-day signature table](screenshots/547-windows-dashboard-signature-table-attack-day.png)

### Apache Web Server Monitoring

Panels: HTTP Method, ClientIP Location (map), Top 10 ClientIP Countries, Top URIs, Server errors, and User Agents.

![HTTP Method and ClientIP Location](screenshots/535-apache-dashboard-method-map.png)

![Countries, URIs, server errors, and user agents](screenshots/536-apache-dashboard-countries-uris-errors-agents.png)

## Key findings

- **Baselines first.** Per-hour counts with mean + 2σ thresholds turned raw logs into alertable signals, for example the non-US Apache spike (120 vs ~119) and the failed-event hour on the Windows server (35 vs ~26.6).
- **Windows attack pattern.** On Mar 25 the data shows a burst of account lockouts (896 in one hour) followed by a burst of password reset attempts (1,258 in one hour), with two accounts (`user_a`, `user_k`) accounting for most of the activity. This pattern is consistent with a credential attack followed by account abuse, and is easy to see once compared against the Mar 24 baseline.
- **Not every threshold fires.** Some searches (successful logons, account deletions) returned no results at their thresholds, which is a valid outcome: the baseline was not exceeded.
- **Apache attack window.** GET and POST make up almost all traffic, with 83.3% of responses returning 200, and POST requests clustered in two hours.

## Build process (dashboard edit mode)

<details>
<summary>Screenshots taken while building the dashboards</summary>

**Windows Server Monitoring**

![User Count panel added](screenshots/519-windows-dashboard-edit-user-count.png)

![Signature Count and Accounts_Created panels](screenshots/520-windows-dashboard-edit-signature-count-gauge.png)

![Signatures and Users per Hour, Mar 24 baseline](screenshots/524-windows-dashboard-edit-signatures-users.png)

![Signatures and Users per Hour, Mar 25 spikes](screenshots/525-windows-dashboard-edit-spike-view.png)

![Signature Count and User Count pies](screenshots/526-windows-dashboard-edit-pies.png)

![Accounts Created marker gauge](screenshots/527-windows-dashboard-edit-accounts-created.png)

![Accounts Created gauge in edit mode](screenshots/548-windows-dashboard-accounts-created-gauge.png)

**Apache Web Server Monitoring**

![HTTP Method and ClientIP Location panels](screenshots/532-apache-dashboard-edit-method-map.png)

![Top 10 ClientIP Countries and Top URIs panels](screenshots/533-apache-dashboard-edit-countries-uris.png)

![Server errors and User Agents panels](screenshots/534-apache-dashboard-edit-errors-useragents.png)

![User Agents panel](screenshots/540-apache-dashboard-edit-user-agents.png)

![HTTP Method traffic, Mar 17 to 20](screenshots/538-apache-dashboard-edit-method-map-all-time.png)

![Top Countries and Top URIs, wider time range](screenshots/539-apache-dashboard-edit-countries-uris-all-time.png)

</details>
