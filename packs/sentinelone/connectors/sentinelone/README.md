# SentinelOne EDR

The management console of SentinelOne Singularity, through its Management API v2.1. This connector does what an
analyst does with the console during an incident: find an endpoint and cut it off the network, read a threat and
kill, quarantine or roll back, take the file of a threat or files and logs of an endpoint as artifacts of the
incident, block a hash, write a detection rule, run a script, start a forensic collection. It brings the threats
of the console in as incidents, and keeps each incident in step with its threat when its instance says so. It has
142 commands.

It was written from SentinelOne's own reference of the API, the one the console shows to a signed-in user. It was
not run against a real console: the connector says `verified: false` until someone has.

The searches of the Singularity Data Lake (PowerQuery) and the alerts of the Singularity Operations Center are the
other connector, **SentinelOne SIEM**: they take the token another way.

## The token

The API token of a **service user** of the console (Settings, Users, Service Users), sent as
`Authorization: ApiToken …`. Its role decides what the commands may do: give it what the playbooks need and no
more. An instance can take the token from a stored credential (Settings, Automation, Credentials) instead of
holding it itself. "Test the instance" reads the version of the console (`GET /system/info`), which needs a valid
token and no permission on endpoints.

## A command that acts always names what it acts on

SentinelOne applies an action whose filter is empty to **everything the token reaches**: every endpoint, every
threat. So every command here that changes something takes the ids it is for, and is stopped before anything is
sent when they are empty (a field of the playbook that came out blank): the step fails and says which argument
had nothing in it. Ids are given one at a time, as a list, or separated by commas.

Two commands take the console's own filter instead, to act on whatever matches: `run-agent-action` and
`mitigate-threats`. Their filter is required, and is refused when it is empty or when one of its fields is.
`count-agents` says how many endpoints a filter reaches before it is used.

Every command that changes an endpoint or the console is marked as one that changes the outside, so a playbook
can ask for an approval before it runs, and a dry run sends nothing.

## Files

These commands keep a file as an artifact of the incident the playbook works on, as it came, and give its
`artifact`, `name`, `sha256`, `size` and `type`.

| Command | What it keeps | How it gets it |
| --- | --- | --- |
| `fetch-threat-file` | the file of a threat, in a zip protected by the password given, **unpacked** | asks the agent, waits for the upload (15 minutes at most), downloads it from the console |
| `fetch-agent-files` | up to 10 files of an endpoint (10 MB in all), in a zip protected by the password given, **unpacked** | the same |
| `fetch-agent-logs` | the logs of an agent | the same; the number of the activity that announces the upload is an argument |
| `download-agent-upload` | any upload of an agent, by the id of its activity | one download from the console |
| `download-threat-from-cloud` | the file of a threat the console holds in its cloud | asks for a link, then follows it |
| `download-event-file` | the file of the source process of a Deep Visibility event | asks for a link, then follows it |
| `download-script-result` | the output of a finished script task | asks for a link, then follows it |
| `download-forensic-collection` | what a forensic collection uploaded | reads the task, asks for a link, then follows it |
| `export-agents`, `export-threats`, `export-activities`, `export-blocklist`, `export-exclusions`, `export-unified-exclusions`, `export-threat-events`, `export-threat-timeline`, `export-mitigation-report` | the list as the console exports it (CSV, or JSON for the unified exclusions) | one request |

### Unpacking

The two fetches ask the agent for an archive protected by a password that the request itself sets, so the same
password opens it: the archive is kept as it came, and **each file inside it becomes an artifact of the incident
too**. The commands give `files` (each with its name in the archive, `type`, `size`, `sha256`, `artifact`),
`count`, and `skipped` (what was left out, and why). Nothing inside is run or opened: it is unpacked in memory
and written to the store. An upload that is not a zip, or that the password does not open, is evidence all the
same: **the archive is kept as it came**, in the incident, nothing inside it is, and the step fails with a
sentence that says why and names the artifact ("The password does not open the archive: nothing was unpacked.
The archive was kept as file-…"). The node `nik.unpack-artifact` opens that artifact later with the right
password; tried again, the fetch keeps no second copy (the same bytes are the same artifact).

The password is a required argument, is never written in the connector, and is treated as a secret: it is in no
record of the step. For files fetched from an endpoint the console wants 10 characters or more, with upper and
lower case letters, digits and symbols; use the same for the file of a threat.

The other commands do not unpack: the reference does not say what the console hands over there (the output of a
script, a collection, a file from the cloud may or may not be an archive), and a command that unpacked something
that is not a zip would fail every time. They keep the file as it came, and the node `nik.unpack-artifact`
opens it when it is an archive, with the password the run or the collection set.

Waiting for an upload, a fetch first looks at the newest upload the console already has for that threat or that
agent, and takes only one that came after: an archive fetched last week, with another password, is not mistaken
for this one.

### Files that come from another host

`download-threat-from-cloud`, `download-event-file`, `download-script-result` and `download-forensic-collection`
ask the console for a link and follow it. A connector reaches its own instance and the hosts its file lists by
name, and SentinelOne's reference names no host for these links: they may be on the console itself, or on a
storage host that differs with the region and the tenant. There are two ways to have the file.

**In the instance.** *Hosts downloads may come from* (Settings, Connectors, the instance, Connection) takes the
storage hosts of your console, separated by commas: a name (`files.example.com`) or every host under a name
(`*.storage.example.com`). The four commands then follow a link, or a redirect, to one of those hosts, over
https, **without the token and without any header of the connector**, which is what a link that carries its own
signature wants. Only these downloads go there: no other command does. The field is empty at first; the first
time a link leads elsewhere the step fails and says which host it was and where to add it ("…goes to
s1-files.example.net, not to its instance: add it under Hosts downloads may come from in the instance if it is
the vendor's storage"), so the name to write is the one the step gives. An address inside your network is
refused whatever the field says.

**In the playbook.** Without listing the host, a playbook does it in three nodes:

1. the command that gives the link: `get-threat-cloud-link`, `get-event-file-link`, `get-script-results` or
   `get-forensic-collection-link`;
2. `nik.download-file` with that link. The host must be among those the playbook may reach, and no credentials
   are sent with the request, which is what a link that carries its own signature wants;
3. `nik.unpack-artifact` on the artifact it kept, when it is an archive.

## What a threat comes in as

Fetching asks for the threats created since the last cycle, oldest first (`createdAt__gte`, `sortBy=createdAt`),
100 a page. The mapper makes an incident named after the threat and the endpoint, with the classification and the
path as details, the confidence level as severity, and the alert, the host and the file in the context.

## Commands

"Changes" marks a command that changes an endpoint or the console; "File" one that keeps a file.

### Agents (5)

The token needs: Viewing endpoints.

| Command | What it does | |
| --- | --- | --- |
| `get-agent` | The agents that match: by a part of the computer name, by id, by user, by address, by state. |  |
| `count-agents` | How many agents match, without reading them: to know how many an action would reach. |  |
| `get-agent-applications` | The applications installed on one endpoint, as its agent last reported them. |  |
| `export-agents` | The agents that match, as the CSV file the console exports (50 000 lines at most), kept as an artifact. | File |
| `get-endpoint-tags` | The tags that can be put on endpoints, with how many endpoints carry each. |  |

### Agent actions (21)

The token needs: The permission for each action on endpoints (isolate, scan, restart, shut down, fetch files and
logs, tags, move to a group). The reference names roles for two of them: disabling and enabling an agent is for
Admin, IR Team and IT; marking an agent as up to date is not open to the SOC role.

| Command | What it does | |
| --- | --- | --- |
| `isolate-agent` | Cut an endpoint off the network: every connection is dropped but the one to the SentinelOne console, so it can still be analysed and cleaned. | Changes |
| `reconnect-agent` | Put an isolated endpoint back on the network. | Changes |
| `scan-agent` | Start a full disk scan on an endpoint: local drives only, and what it finds is handled as the policy says. | Changes |
| `abort-agent-scan` | Stop the full disk scan that is running on an endpoint. | Changes |
| `request-agent-logs` | Ask an agent to upload its logs to the console. They arrive later as an upload of the agent: get-activities finds it, download-agent-upload keeps it. | Changes |
| `fetch-agent-logs` | Ask an agent for its logs, wait until it has uploaded them (15 minutes at most) and keep the archive as an artifact. | Changes · File |
| `fetch-agent-files` | Have an agent upload up to 10 files of its endpoint (10 MB in all) as a zip protected by the password given, wait for it (15 minutes at most), keep it as an artifact and unpack it: each file inside becomes an artifact too. | Changes · File |
| `download-agent-upload` | Keep as an artifact something an agent uploaded to the console (its logs, fetched files, a threat file), by the id of the activity that announced it. It is kept as it came: nik.unpack-artifact opens it when it is an archive, with the password the request that asked for it set. | File |
| `refresh-agent-firewall-rules` | Have an agent read its Firewall Control rules from the console now, instead of at its next cycle. | Changes |
| `set-agent-firewall-logging` | Say where an agent writes the connections Firewall Control blocks: to its local log, to the activities of the console, or both. | Changes |
| `broadcast-message` | Show a message to the person at the endpoint (Windows and macOS). | Changes |
| `restart-agent` | Restart the endpoint. Whoever is using it loses what was not saved: broadcast-message can warn first. | Changes |
| `shutdown-agent` | Switch the endpoint off. It cannot be reached again until someone turns it on: to contain an infection, isolate-agent keeps it analysable. | Changes |
| `tag-agent` | Put a tag on an endpoint, take one off, or replace the tags that have the same key. | Changes |
| `set-agent-external-id` | Write the customer identifier of an endpoint: a free text shown in its details, to mark it. | Changes |
| `mark-agent-up-to-date` | Tell the console that the version of an agent is the current one, when it has not noticed. | Changes |
| `disable-agent` | Turn the protection of an agent off: it stays connected to the console but detects and stops nothing until it is enabled again. | Changes |
| `enable-agent` | Turn the protection of a disabled agent back on. | Changes |
| `refresh-agent-applications` | Have an agent report the applications installed on its endpoint again. | Changes |
| `move-agents-to-group` | Move endpoints to another group of their site: they take the policy of that group (a group with a strict policy is a way to quarantine). | Changes |
| `run-agent-action` | Do one thing to every agent a filter matches, in the console's own filter fields. The filter is required and no field of it may be empty: count-agents says how many it reaches. | Changes |

### Endpoint tags (3)

The token needs: Managing endpoint tags in the scope.

| Command | What it does | |
| --- | --- | --- |
| `create-endpoint-tag` | Make a tag that endpoints can carry: a key and a value. | Changes |
| `update-endpoint-tag` | Change the key, the value or the description of an endpoint tag. | Changes |
| `delete-endpoint-tags` | Delete endpoint tags, by id. The endpoints that carried them lose them. | Changes |

### Threats (28)

The token needs: Viewing threats for the reads. The reference says mitigating, fetching the file of a threat,
adding to the blocklist and marking as a threat are for the roles Admin, IR Team and SOC, and that only the
threats the token may mitigate are counted in `affected`.

| Command | What it does | |
| --- | --- | --- |
| `get-threats` | Threats: by id, by the hash of the file, by state, by endpoint, by time. |  |
| `get-threat-notes` | The notes written on a threat. |  |
| `add-note` | Write a note on a threat. | Changes |
| `update-threat-note` | Replace the text of a note of a threat. | Changes |
| `delete-threat-note` | Delete a note of a threat. | Changes |
| `mitigate-threat` | Act on a threat. kill stops the processes; quarantine moves the files away, encrypted; remediate undoes what the threat changed (Windows and macOS); rollback-remediation restores the files from the shadow copies (Windows); un-quarantine puts the files back; network-quarantine isolates the endpoint. | Changes |
| `mitigate-threats` | Act on every threat a filter matches, in the console's own filter fields. The filter is required and no field of it may be empty. The actions are those of mitigate-threat. | Changes |
| `add-threat-to-blocklist` | Put the SHA-1 of the file of a threat in the blocklist, for the group, the site or the account of its endpoint, or for everyone: agents there stop the file from running. | Changes |
| `add-threat-to-exclusions` | Make an exclusion from a threat: agents stop raising it. An exclusion is a hole in the protection: only for what is surely harmless, as narrow as it can be. | Changes |
| `get-exclusion-options` | The kinds of exclusion that can be made from a threat (a path, the hash of its file…). |  |
| `fetch-threat-file` | Have the agent upload the file of a threat as a zip protected by the password given, wait for it (15 minutes at most), keep it as an artifact and unpack it: the file inside becomes an artifact too. The endpoint must be reachable. | Changes · File |
| `get-threat-cloud-link` | Where the file of a threat can be downloaded from, when the console keeps it in its cloud: the link and the name of the file. |  |
| `download-threat-from-cloud` | Keep as an artifact the file of a threat that the console holds in its cloud, as it came. It follows the link only when the link is on the console itself. When it is on another host: get-threat-cloud-link gives the link, nik.download-file fetches it (the host must be among those the playbook may reach; no credentials go with it), and nik.unpack-artifact opens it when it is an archive. | File |
| `get-threat-events` | What the agent recorded around a threat: the processes, files, connections and registry changes of its storyline. |  |
| `export-threat-events` | The events around a threat as the file the console exports, kept as an artifact. | File |
| `get-threat-timeline` | What happened to a threat, in order: detection, what the agent did, what people did. |  |
| `export-threat-timeline` | The timeline of a threat as the file the console exports, kept as an artifact. | File |
| `set-threat-incident` | Set the incident status of a threat, and its analyst verdict with it if wanted. | Changes |
| `set-threat-verdict` | Set the analyst verdict of a threat. | Changes |
| `set-threat-ticket` | Write on a threat the id of the ticket that follows it elsewhere (the incident in Nik, a ticket in ServiceNow or Jira). | Changes |
| `disable-engines` | Turn detection engines of the agents off, to find the one that raises false positives. It weakens the protection wherever the token reaches: the console's own policy pages are where it is turned back on. | Changes |
| `get-quarantined-files` | The files the agent moved to quarantine for a threat: name, path and size. |  |
| `export-threats` | The threats that match, as the CSV file the console exports (20 000 lines at most), kept as an artifact. | File |
| `export-mitigation-report` | The report of what a mitigation did (files, processes, registry keys), as the CSV file the console gives, kept as an artifact. | File |
| `disconnect-container` | Cut the container of a threat off the network. | Changes |
| `reconnect-container` | Put the container of a threat back on the network. | Changes |
| `mark-as-threat` | Turn something seen in Deep Visibility into a threat, by its storyline: the console raises it and adds its file to the blocklist. | Changes |
| `block-event-hash` | Put in the blocklist a SHA-1 seen in Deep Visibility, for the group, the site or the account of the agent that saw it, or for everyone. | Changes |

### Alerts of custom detection rules (4)

The token needs: Viewing and updating the alerts of custom rules (STAR).

| Command | What it does | |
| --- | --- | --- |
| `get-alerts` | The alerts raised by custom detection rules (STAR): by id, by rule, by endpoint, by state, by time. |  |
| `set-alert-verdict` | Set the analyst verdict of an alert of a custom detection rule. | Changes |
| `set-alert-incident` | Set the incident status of an alert of a custom detection rule. | Changes |
| `mitigate-alert` | Treat an alert as a threat and act on it, by the storyline of the alert and the agent that reported it. The actions are those of mitigate-threat. | Changes |

### Blocklist (6)

The token needs: Viewing the blocklist for the reads. The reference says the IT role may not add to it nor delete
from it; Admin, IR Team and SOC may.

| Command | What it does | |
| --- | --- | --- |
| `get-blocklist` | The hashes in the blocklist of a scope: by hash, by id, by who put them there. |  |
| `add-hash-to-blocklist` | Put the hash of a file in the blocklist, for some sites, groups or accounts, or for the whole tenant when none is named: agents there stop the file from running. | Changes |
| `update-blocklist-item` | Change an item of the blocklist: its description, its operating system, its hash. | Changes |
| `delete-blocklist-items` | Take items out of the blocklist, by id: the agents let those files run again. | Changes |
| `validate-blocklist-item` | Ask whether SentinelOne advises against blocking a hash, or does not allow it, before adding it. |  |
| `export-blocklist` | The blocklist of a scope as the CSV file the console exports, kept as an artifact. | File |

### Exclusions (9)

The token needs: Viewing and managing exclusions in the scope.

| Command | What it does | |
| --- | --- | --- |
| `get-exclusions` | The exclusions of a scope: what the agents there do not raise. |  |
| `create-exclusion` | Make an exclusion for sites, groups, accounts or the whole tenant: the agents there stop raising what it names. Every exclusion is a hole in the protection: as narrow as it can be. | Changes |
| `update-exclusion` | Change an exclusion. | Changes |
| `delete-exclusions` | Delete exclusions, by id: the agents raise those things again. | Changes |
| `validate-exclusion` | Ask whether SentinelOne advises against an exclusion, or does not allow it, before making it. |  |
| `export-exclusions` | The exclusions of a scope as the CSV file the console exports, kept as an artifact. | File |
| `get-unified-exclusions` | The exclusions as the newer, unified list keeps them (those of every engine together, with how often each was hit). |  |
| `delete-unified-exclusion` | Delete one exclusion of the unified list, by its id and its kind. | Changes |
| `export-unified-exclusions` | The exclusions of the unified list as the JSON file the console exports, kept as an artifact. | File |

### Deep Visibility (4)

The token needs: Deep Visibility (the Complete licence) and its permission to search.

| Command | What it does | |
| --- | --- | --- |
| `search-deep-visibility` | Run a Deep Visibility query (S1QL 1.0) over a time range and read its events. SentinelOne marks this API as deprecated: run-query of the SentinelOne SIEM connector is the one that replaces it. |  |
| `get-event-file-link` | Where the file of the source process of a Deep Visibility event can be downloaded from: the link and the name of the file. |  |
| `download-event-file` | Keep as an artifact the file of the source process of a Deep Visibility event, as it came. It follows the link only when the link is on the console itself. When it is on another host: get-event-file-link gives the link, nik.download-file fetches it (the host must be among those the playbook may reach; no credentials go with it), and nik.unpack-artifact opens it when it is an archive. | File |
| `get-saved-filters` | The filters of endpoints people saved in the console: the id of one can be the filterId of run-agent-action. |  |

### Custom detection rules (10)

The token needs: Viewing and managing custom detection rules; a rule is seen only from the scope it was made in.

| Command | What it does | |
| --- | --- | --- |
| `get-detection-rules` | The custom detection rules (STAR) of a scope: by name, by state, by severity. |  |
| `create-detection-rule` | Make a custom detection rule for sites, groups, accounts or the whole tenant. Active, it raises alerts from then on; with network_quarantine it isolates endpoints by itself. | Changes |
| `update-detection-rule` | Change a custom detection rule. The console wants the whole rule again: name, severity, state, kind and expiration mode, with what changes. | Changes |
| `enable-detection-rules` | Turn custom detection rules on, by id: they raise alerts from then on. | Changes |
| `disable-detection-rules` | Turn custom detection rules off, by id: they stop raising alerts. | Changes |
| `delete-detection-rules` | Delete custom detection rules, by id. | Changes |
| `get-managed-rules` | The detection rules SentinelOne maintains (the library), as a scope has them: which are on, which are off. |  |
| `enable-managed-rules` | Turn rules of SentinelOne's library on for a scope: each becomes an active rule there. | Changes |
| `disable-managed-rules` | Turn rules of SentinelOne's library off for a scope. | Changes |
| `get-log-collection-rules` | The rules that say which logs the agents send to the Data Lake, for a scope. |  |

### Remote scripts (14)

The token needs: Remote Script Orchestration: viewing the library, running scripts, uploading them, approving
runs. A run may need the approval of a second person (the guardrails of the console).

| Command | What it does | |
| --- | --- | --- |
| `get-scripts` | The scripts of the script library that can be run on endpoints: SentinelOne's own and those uploaded. |  |
| `get-script-content` | The text of a script of the library, to read it before running it. |  |
| `run-script` | Run a script of the library on endpoints, with the rights of the agent (the system). It answers at once with the id of the task: get-script-tasks follows it, download-script-result keeps its output. | Changes |
| `get-script-tasks` | How the tasks of a run of a script are doing, one for each endpoint: created, pending, in progress, completed, failed. |  |
| `get-script-results` | Where the output of finished script tasks can be downloaded from: a link and a file name for each task. |  |
| `download-script-result` | Keep as an artifact the output of a finished script task, as it came (the password the run set, if any, is what opens it). It follows the link only when the link is on the console itself. When it is on another host: get-script-results gives the link, nik.download-file fetches it (the host must be among those the playbook may reach; no credentials go with it), and nik.unpack-artifact opens it when it is an archive. | File |
| `upload-script` | Add a script Nik holds as an artifact to the script library, for a scope. The console takes a new script as a file only: its text alone is accepted just to copy an existing one. | Changes |
| `get-pending-script-runs` | The runs of scripts that wait for a second person to approve them in the console. |  |
| `review-pending-script-run` | Approve or decline a run of a script that waits for approval. Approved, the script runs on its endpoints. | Changes |
| `check-script-guardrail` | Whether running a script on some agents would need the approval of a second person, as the guardrails of the console are set. |  |
| `schedule-script` | Have a script of the library run on endpoints at a later time, once or again and again. | Changes |
| `get-scheduled-tasks` | The scripts and forensic collections that are scheduled to run later. |  |
| `update-scheduled-task` | Change when a scheduled task runs. The console wants the three parts of the schedule again: the time, the end and the recurrence. | Changes |
| `delete-scheduled-tasks` | Delete scheduled tasks, by id: they will not run. Those that cannot be deleted are skipped. | Changes |

### Forensic collections (9)

The token needs: Remote Ops Forensics: viewing profiles, starting collections, reading their files.

| Command | What it does | |
| --- | --- | --- |
| `get-forensic-profiles` | The profiles a forensic collection can follow: each a set of artifacts to collect. |  |
| `get-forensic-profile` | One collection profile, with the artifacts it collects. |  |
| `get-forensic-artifact-types` | Every kind of artifact a forensic collection can take, by operating system. |  |
| `start-forensic-collection` | Have agents collect the artifacts of a profile (event logs, prefetch, registry hives…) and upload them. It answers at once: get-forensic-collection follows the task, download-forensic-collection keeps the archive. | Changes |
| `get-forensic-collection` | What a collection task gave: the state of each artifact, and what describes the collected file once it is uploaded. |  |
| `find-forensic-collection` | Whether a collected file exists for a storyline of an agent (a collection the policy started by itself on a threat), and what describes it. |  |
| `get-forensic-collection-link` | A link, valid for a short time, to download a collected file, from what describes it (get-forensic-collection, find-forensic-collection). |  |
| `download-forensic-collection` | Keep as an artifact what a collection task uploaded, as it came (the password the collection set, if any, is what opens it). It follows the link only when the link is on the console itself. When it is on another host: get-forensic-collection-link gives the link, nik.download-file fetches it (the host must be among those the playbook may reach; no credentials go with it), and nik.unpack-artifact opens it when it is an archive. | File |
| `schedule-forensic-collection` | Have agents collect the artifacts of a profile at a later time, once or again and again. | Changes |

### Threat intelligence (5)

The token needs: Viewing and managing the indicators of threat intelligence, in an account at least.

| Command | What it does | |
| --- | --- | --- |
| `get-iocs` | The indicators of compromise the console matches what the agents see against: by value, by kind, by source. |  |
| `create-ioc` | Add an indicator of compromise to the console's threat intelligence, for accounts, sites or the whole tenant: what agents see is matched against it until it expires. | Changes |
| `delete-iocs` | Delete indicators of compromise from the console's threat intelligence, by UUID, in the accounts named. | Changes |
| `create-iocs-from-stix` | Add the indicators of a STIX 2.1 bundle to the console's threat intelligence: file hashes, addresses, domains and URLs. | Changes |
| `get-hash-verdict` | What SentinelOne's reputation says of a SHA-1: malicious, not malicious, or unknown. SentinelOne marks this call as deprecated. |  |

### Applications and vulnerabilities (6)

The token needs: Application Risk Management (viewing).

| Command | What it does | |
| --- | --- | --- |
| `get-application-risks` | The applications found on endpoints that have known vulnerabilities, one line for each version: how many CVEs, how many endpoints, the highest severity. |  |
| `get-application-cves` | The CVEs of one application (by the id get-application-risks gives). |  |
| `get-vulnerable-endpoints` | The endpoints that have a vulnerable application installed. |  |
| `get-cves` | The CVEs found across the endpoints, one line for each CVE on each endpoint. |  |
| `get-application-inventory` | The applications installed across the endpoints, by name and vendor, with how many endpoints have each. |  |
| `get-application-endpoints` | The endpoints an application is installed on, with the version each has. |  |

### The tenant: accounts, sites, groups, activities (12)

The token needs: Viewing accounts, sites, groups, policies and the activity log.

| Command | What it does | |
| --- | --- | --- |
| `get-accounts` | The accounts the token can see. |  |
| `get-account` | One account. |  |
| `get-sites` | The sites the token can see. |  |
| `get-site` | One site. |  |
| `get-groups` | The groups of endpoints, in the sites named or in all those the token can see. |  |
| `get-group` | One group. |  |
| `get-site-policy` | The policy that applies to a site: what the agents there do with a threat and with something suspicious, and where the policy is inherited from. |  |
| `get-group-policy` | The policy that applies to a group: what the agents there do with a threat and with something suspicious, and where the policy is inherited from. |  |
| `get-activities` | What happened in the console, as its activity log tells it: by kind, by agent, by threat, by time. |  |
| `get-activity-types` | Every kind of activity the console writes, with its number: what get-activities and the fetch commands filter by. |  |
| `export-activities` | The activities that match, as the CSV file the console exports, kept as an artifact. | File |
| `get-tags` | The tags of the console's rules, by kind: those of Firewall Control rules, of Device Control rules, of network quarantine. |  |

### Network discovery, devices and firewall rules (4)

The token needs: Viewing Network Discovery, Device Control and Firewall Control.

| Command | What it does | |
| --- | --- | --- |
| `get-network-discovery` | The devices Network Discovery (Ranger) saw on the networks of the endpoints: address, kind, system, whether an agent manages them. |  |
| `get-unprotected-endpoints` | The computers seen on the networks that could have an agent and have none. |  |
| `get-device-control-events` | What Device Control saw on endpoints: USB and Bluetooth devices connected, allowed or blocked. |  |
| `get-firewall-rules` | The Firewall Control rules of a scope. The console wants one of: a name, a state, an operating system, an action or a scope. |  |

### The console (2)

The token needs: Any valid token.

| Command | What it does | |
| --- | --- | --- |
| `get-system-info` | The version of the console: build, release, patch, and the newest version of the agent it knows. |  |
| `get-system-status` | Whether the console says it is up. It answers without looking at the token. |  |

## Left out on purpose

The reference holds 830 operations. Those that administer the console are not here: they are of no use in a
playbook, and each one would widen what a stolen token can do.

- **Users and access**: users, roles, service users, API tokens, two-factor authentication, sign-in and SSO.
- **Settings**: SSO, SMTP, syslog, SMS, Active Directory, notifications, the system configuration.
- **Licences and tenants**: licences, SKUs and add-ons; making, changing, deleting, expiring and reactivating
  accounts and sites; MSSP provisioning.
- **Policies**: making, changing and reverting them. Reading the policy of a site or of a group is here.
- **The agent software**: packages, upgrades and upgrade policies, with their maintenance windows (the "rule
  maintenance windows" of the reference belong to those policies, not to detection rules); uninstalling,
  decommissioning, approving or rejecting an uninstall; uninstall passwords and passphrases; moving agents between
  sites or to another console; randomising the UUID; resetting the local configuration; configuration overrides;
  local upgrade authorisation.
- **Remote Shell**: it opens an interactive session a playbook cannot type into. Remote scripts are what run
  commands on an endpoint.
- **Remote profiling, Cloud Funnel, data tables, Hyperautomation workflows, VCS and CI/CD integrations, reports,
  the RSS feed, the graph query builder, identity (Active Directory) configuration, tunnels, access tokens,
  marketplace applications, tag rules.**
- **Writes to Device Control and Firewall Control rules**, and the changes to an asset of the unified inventory.

Left out because the reference does not say enough to write them:

- **The unified asset inventory** (`/xdr/assets/…`, "Perform action"): the reference names the action as an
  enumeration and prints none of its values, so nothing says whether it adds a response the agent actions lack.
- **Creating and changing a unified exclusion**: the reference gives these two no body. Reading, deleting and
  exporting them are here, and so is everything on the classic exclusions.
- **The processes of an agent**: the reference marks the call as obsolete and says it answers an empty list.
- **The other Deep Visibility calls marked deprecated** (events by type, process state, the older Power Query):
  `search-deep-visibility` is kept as it was, and new searches belong to `run-query` of SentinelOne SIEM.
- **Imports of the blocklist and of exclusions from a file.**

## What the reference does not say

- **The values of its enumerations.** It names the type and prints no value. Where its own examples and
  descriptions give values (the mitigation actions, the engines, the states of a Deep Visibility query, the
  verdicts and incident states of a threat), they are choices here. Elsewhere the argument is a free text and its
  description names the words the console shows: the scope of a blocklist entry, the kinds of exclusion, the
  severity and the state of a rule, the output destination of a script, the upper-case verdicts and states of an
  alert.
- **The capitals of eight query parameters.** It prints the parameters of an address in lower case; the capitals
  here are those of the same names in its tables of bodies. Eight names are in no table and follow the same
  convention: `activityTypes`, `threatIds`, `eventTypes`, `processName__like`, `downloadToken`, `applicationIds`,
  `cveId__contains`, `endpointName__contains`.
- **Which activity announces an upload.** It gives the address an upload is read from and says to look the number
  up in the list of activity types. `fetch-threat-file` waits for 86 and `fetch-agent-files` for 80, the numbers
  the integrations of other products wait for; both are arguments. `fetch-agent-logs` asks for the number.
- **That a fetched archive is a zip.** It says the fetched files come as an archive opened with the password,
  and calls the password of a threat file a file encryption password; the format is the one the integrations of
  other products open.
- **Whether an answer is one object or a list.** Creating a blocklist entry, an exclusion or an indicator is read
  as a list; the tags of `tag-agent` are sent as a list.
- **Two answers**: moving agents to a group, and starting a forensic collection (it says 202 and no body).

## Mirroring (new in 1.2, needs Nik 6.10)

In the *Fetch* part of an instance, *Mirroring* says which way the incidents it fetches are kept in step with their
threats: *None* (as before), *In*, *Out* or *In-out*. The object is the threat the incident was made from, by its id.
Only commands of this connector are used:

| | What | With |
| --- | --- | --- |
| In | the threat is read again every two minutes; its **incident status** becomes the status of the incident and its **analyst verdict** the close reason | `get-threats` by id (`GET /threats`) |
| In | the **notes** of the threat become notes of the War Room, signed by who wrote them | `get-threat-notes` (`GET /threats/{id}/notes`) |
| In | while the incident is closed, the last note a **person** wrote becomes its close notes (new in 1.3, needs Nik 6.11) | the same notes |
| Out | the status of the incident and its close reason are written as the incident status and the analyst verdict, in one request | `set-threat-incident` (`POST /threats/incident`) |
| Out | a note tagged `mirror` becomes a note of the threat | `add-note` (`POST /threats/notes`) |

How the two vocabularies meet is in the mappers of the pack, which are yours to change:

| SentinelOne | Nik |
| --- | --- |
| incident status `unresolved` · `in_progress` · `resolved` | status open · in progress · closed (both ways) |
| analyst verdict `true_positive` · `false_positive` | close reason *Resolved* · *False positive* (coming in) |
| analyst verdict `true_positive` · `false_positive` · `suspicious` | close reason *Resolved* or *True positive* · *False positive* · *Suspicious* (going out; any other reason sends no verdict) |

Things to know:

- A field a person set in Nik is kept when the threat says otherwise, unless the mapper marks it as winning over
  edits. Setting the status twice leaves the threat as setting it once, so an update cut by a restart is sent
  again; a note is never sent twice.
- A threat that is not in the console any more is said once on the incident and read no more.
- The console keeps the note written on resolving as one more note of the threat. The instance field **Note authors
  that are automations** (Hyperautomation when empty) names the authors whose notes are not taken as close notes;
  separate several with commas. With only such notes, the close notes stay empty. Close notes written in Nik stay.
- With these mappers, a threat that is already in progress or resolved when it is fetched makes an incident that
  starts in progress or closed.
- The token needs what `set-threat-incident` and `add-note` need to mirror out; viewing is enough to mirror in.
- The alerts of custom detection rules are another object, which the fetch does not bring and for which the
  reference gives no notes: they are not mirrored. Their status and verdict are still set by the commands
  `set-alert-incident` and `set-alert-verdict`.
