"""Column allowlists for the tabular views.

A tabular view keeps only the columns its tool declares and reports how many it dropped
as a count, never by name: the model knows the row is a projection and cannot ask for a
dropped column by name. ``AdditionalFields`` and ``_raw`` are on no allowlist; that is
where nested JSON with service account passwords and NTLM hashes lives. Display-name and
coordinate columns are on no allowlist either: personal data stays in the artifact, the
user principal name and email are the join keys and stay, and so do ``City`` and
``Country``, the substance of a travel alert.

Aggregates are allowed structurally: KQL names ``count_`` and ``<agg>_<column>``, SPL
names ``count`` and ``<agg>(<field>)``, kept only when the underlying column is allowed.
"""

import re

HUNTING_COLUMNS: frozenset[str] = frozenset(
    {
        # Common
        "Timestamp",
        "ReportId",
        "ActionType",
        "DeviceId",
        "DeviceName",
        "AlertId",
        "Title",
        "Severity",
        "Category",
        "DetectionSource",
        "ServiceSource",
        "AttackTechniques",
        "EntityType",
        # Accounts, sign-ins
        "AccountName",
        "AccountDomain",
        "AccountUpn",
        "AccountObjectId",
        "AccountSid",
        "UserPrincipalName",
        "LogonType",
        "LogonId",
        "ErrorCode",
        "ResultType",
        "ResultDescription",
        "IsExternalUser",
        "IsManaged",
        "IsCompliant",
        "Application",
        "ApplicationId",
        "ClientAppUsed",
        "ConditionalAccessStatus",
        "AuthenticationRequirement",
        "RiskLevelDuringSignIn",
        "RiskState",
        "Protocol",
        "FailureReason",
        "Location",
        "Country",
        "State",
        "City",
        # Network
        "IPAddress",
        "LocalIP",
        "LocalPort",
        "RemoteIP",
        "RemotePort",
        "RemoteUrl",
        "RemoteIPType",
        "SourceIP",
        "DestinationIP",
        "DestinationPort",
        "NetworkMessageId",
        # Files and processes
        "FileName",
        "FolderPath",
        "SHA1",
        "SHA256",
        "MD5",
        "FileSize",
        "FileOriginUrl",
        "FileOriginReferrerUrl",
        "ProcessId",
        "ProcessCommandLine",
        "ProcessCreationTime",
        "ProcessIntegrityLevel",
        "ProcessTokenElevation",
        "InitiatingProcessId",
        "InitiatingProcessFileName",
        "InitiatingProcessFolderPath",
        "InitiatingProcessCommandLine",
        "InitiatingProcessCreationTime",
        "InitiatingProcessAccountName",
        "InitiatingProcessAccountDomain",
        "InitiatingProcessAccountUpn",
        "InitiatingProcessSHA256",
        "InitiatingProcessSignerType",
        "InitiatingProcessSignatureStatus",
        "InitiatingProcessParentId",
        "InitiatingProcessParentFileName",
        "InitiatingProcessParentCreationTime",
        "SignerType",
        "SignatureStatus",
        "Signer",
        "Issuer",
        "IsSigned",
        "IsTrusted",
        "IsRootSignerMicrosoft",
        # Registry
        "RegistryKey",
        "RegistryValueName",
        "RegistryValueType",
        "RegistryValueData",
        # Email
        "SenderFromAddress",
        "SenderMailFromAddress",
        "SenderDisplayName",
        "SenderIPv4",
        "RecipientEmailAddress",
        "Subject",
        "DeliveryAction",
        "DeliveryLocation",
        "ThreatTypes",
        "AttachmentCount",
        "UrlCount",
        "Url",
        "UrlDomain",
        # Cloud apps
        "ObjectName",
        "ObjectType",
        "ObjectId",
        "ActivityType",
        "ActivityObjects",
        "IsAnonymousProxy",
        "UserAgent",
        "OSPlatform",
        # Identity, directory
        "TargetAccountUpn",
        "TargetAccountDisplayName",
        "TargetDeviceName",
        "DestinationDeviceName",
        "Port",
        "AdditionalInfo",
        # Device
        "OSVersion",
        "PublicIP",
        "MachineGroup",
        "OnboardingStatus",
        "JoinType",
        "IsAzureADJoined",
        "AadDeviceId",
    }
) - {"SenderDisplayName", "TargetAccountDisplayName"}
"""Defender advanced hunting columns the model may see. Display-name columns are removed
even where they appear in the schema; ``AdditionalFields`` was never in."""

_KQL_AGGREGATE = re.compile(
    r"^(dcount|min|max|sum|avg|make_set|make_list|any|take_any|arg_max|arg_min|countif|"
    r"percentile|stdev|variance)_(.+)$"
)


def hunting_column_allowed(name: str) -> bool:
    if name in HUNTING_COLUMNS or name == "count_":
        return True
    aggregate = _KQL_AGGREGATE.match(name)
    return aggregate is not None and aggregate.group(2) in HUNTING_COLUMNS


SPLUNK_FIELDS: frozenset[str] = frozenset(
    {
        "_time",
        "host",
        "source",
        "sourcetype",
        "index",
        "count",
        "action",
        "app",
        "dest",
        "dest_ip",
        "dest_port",
        "dest_host",
        "src",
        "src_ip",
        "src_port",
        "src_host",
        "src_user",
        "user",
        "user_id",
        "user_agent",
        "signature",
        "signature_id",
        "reason",
        "authentication_method",
        "authentication_service",
        "mfa",
        "session_id",
        "status",
        "http_method",
        "http_user_agent",
        "url",
        "uri_path",
        "bytes",
        "bytes_in",
        "bytes_out",
        "packets",
        "transport",
        "protocol",
        "duration",
        "recipient",
        "sender",
        "subject",
        "message_id",
        "attachment",
        "file_name",
        "file_hash",
        "file_path",
        "file_size",
        "process",
        "process_name",
        "process_id",
        "process_path",
        "process_hash",
        "process_exec",
        "parent_process",
        "parent_process_name",
        "parent_process_id",
        "parent_process_exec",
        "object",
        "object_category",
        "object_attrs",
        "object_path",
        "change_type",
        "result",
        "result_id",
        "dvc",
        "category",
        "severity",
        "priority",
        "risk_score",
        "risk_object",
        "risk_object_type",
        "risk_message",
        "threat_object",
        "threat_object_type",
        "rule_name",
        "search_name",
        "tag",
        "vendor_product",
        "event_id",
        "EventCode",
        "Logon_Type",
        "src_country",
        "dest_country",
        "country",
        "city",
        "region",
        "isp",
        "asn",
        "tenant",
    }
)
"""Splunk CIM fields the model may see. ``_raw`` is not among them."""

_SPL_AGGREGATE = re.compile(r"^(\w+)\((.+)\)$")


def splunk_field_allowed(name: str) -> bool:
    if name in SPLUNK_FIELDS:
        return True
    aggregate = _SPL_AGGREGATE.match(name)
    return aggregate is not None and aggregate.group(2) in SPLUNK_FIELDS
