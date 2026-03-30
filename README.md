# wazuh-windows-file-correlation-rules

Custom Wazuh correlation rules for monitoring Windows file servers and SMB shares.

This repository contains Wazuh rules for detecting:

* delete intent
* confirmed file deletion
* deletion bursts and bulk deletion
* object permission changes
* repeated ACL changes
* suspicious high-volume access to SMB shares that may indicate file copying

The rules are designed for Windows Security events related to file system activity and network share access, and are intended for environments where Wazuh collects Windows Event Channel logs from file servers. Wazuh custom rules support field-based matching and correlation using `if_sid`, `if_matched_sid`, `frequency`, `timeframe`, and `same_field`. ([documentation.wazuh.com][1])

## Required Windows audit events

To use these rules correctly, enable auditing for the following Windows Security events:

* **4659** — A handle to an object was requested with intent to delete
* **4660** — An object was deleted
* **4663** — An attempt was made to access an object
* **4670** — Permissions on an object were changed
* **5145** — A network share object was checked to see whether the client can be granted desired access

These events come from Windows Object Access and Detailed File Share auditing. Event `4663` is generated only when the target object has a matching SACL entry for the requested access, and `5145` belongs to the **Audit Detailed File Share** subcategory. ([Microsoft Learn][2])

## What to enable on Windows

For file server monitoring, enable at least:

* **Advanced Audit Policy → Object Access → Audit File System**
* **Advanced Audit Policy → Object Access → Audit Detailed File Share**
* **SACLs** on the folders and files you want to monitor

If you also want delete-intent and delete-confirmation context from `4659` and `4660`, enable the related Object Access auditing in the environment where those events are produced. Microsoft notes that file and folder audit events depend both on the audit policy and on the effective SACL on the object. ([Microsoft Learn][3])

## What these rules do

### 1. Delete intent detection

The rules detect **Event ID 4659** and raise an alert when a user requests a handle with intent to delete an object.

### 2. File deletion with full path

The rules detect **Event ID 4663** with **DELETE** access and use the object name as the file path in the alert.

This is important because **4660 does not contain the deleted object name**. Microsoft explicitly recommends using `4663` with DELETE access when you need to track object deletion with path context. ([Microsoft Learn][4])

### 3. Deletion confirmation

The rules also track **Event ID 4660** as confirmation that the deletion happened, even though that event only provides the handle and process context, not the full object path. ([Microsoft Learn][4])

### 4. Permission change detection

The rules detect **Event ID 4670** to identify permission or ACL changes on monitored objects. For file objects, Windows includes the object name and path in this event. ([Microsoft Learn][5])

### 5. Repeated and bulk activity correlation

The rules correlate repeated events from the same user over a short time window to detect:

* multiple delete attempts
* bulk deletion
* repeated ACL changes

This is implemented with standard Wazuh rule correlation primitives such as `if_matched_sid`, `frequency`, `timeframe`, and `same_field`. ([documentation.wazuh.com][1])

### 6. Possible file copy from SMB shares

The rules use **Event ID 5145** to detect repeated file access over network shares and flag possible file copying activity.

Windows does not emit a dedicated “file copied from share” event, so this detection is heuristic: repeated `5145` access events from the same user within a time window are treated as a possible copy pattern. This inference is based on how `5145` works: it is generated whenever a network share object is accessed and includes fields such as **Source Address**, **Share Name**, and **Relative Target Name**. ([Microsoft Learn][6])

## Event field usage

These rules rely on Windows Security event fields such as:

* `objectName` for full file path in file system events
* `handleId` for delete confirmation correlation
* `subjectUserName` and `subjectDomainName` for actor attribution
* `processName` for process context
* `shareName`, `relativeTargetName`, and `ipAddress` for SMB access context

For `4663`, Microsoft documents `Object Name` and access values such as `0x1` for read access. For `5145`, Microsoft documents `Relative Target Name`, `Share Name`, `Source Address`, and share access rights such as `ReadData/ListDirectory (0x1 / %%4416)`. ([Microsoft Learn][2])

## Important limitations

* `4660` confirms deletion but does **not** contain the deleted object path. ([Microsoft Learn][4])
* `4663` is more useful for path-aware deletion monitoring, but it also appears for non-delete access, so the access mask must be filtered carefully. ([Microsoft Learn][2])
* `5145` is high-volume and can be noisy on busy file servers, so copy-related thresholds should be tuned for your environment. Microsoft notes that `5145` is generated every time a network share object is accessed. ([Microsoft Learn][6])

## Recommended use case

This ruleset is suitable for:

* Windows file servers
* SMB shares with sensitive data
* monitoring of deletion and permission tampering
* detection of possible mass access or exfiltration-like copy behavior from shared folders

It is best used in environments where audit scope is limited to business-critical shares and where SACLs are applied deliberately to avoid unnecessary log volume. Microsoft recommends monitoring specific object names, share names, relative target names, and sensitive access rights rather than auditing everything indiscriminately. ([Microsoft Learn][2])

## Installation

1. Copy the rule block into:
   `/var/ossec/etc/rules/local_rules.xml`

2. Validate XML:
   `xmllint --noout /var/ossec/etc/rules/local_rules.xml`

3. Test with:
   `/var/ossec/bin/wazuh-logtest -v`

4. Restart Wazuh manager:
   `systemctl restart wazuh-manager`

Wazuh recommends using `wazuh-logtest` to verify decoded fields and rule matches before enabling the rules in production. ([documentation.wazuh.com][1])
