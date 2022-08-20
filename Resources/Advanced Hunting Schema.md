# Advanced Hunting Schema

|Table name|Description|
|:----|:----|
|AlertEvidence|Files, IP addresses, URLs, users, or devices associated with alerts|
|AlertInfo|Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity, including severity information and threat categorization|
|CloudAppEvents|Events involving accounts and objects in Office 365 and other cloud apps and services|
|DeviceEvents|Multiple event types, including events triggered by security controls such as Microsoft Defender Antivirus and exploit protection|
|DeviceFileCertificateInfo|Certificate information of signed files obtained from certificate verification events on endpoints|
|DeviceFileEvents|File creation, modification, and other file system events|
|DeviceImageLoadEvents|DLL loading events|
|DeviceInfo|Machine information, including OS information|
|DeviceLogonEvents|Sign-ins and other authentication events on devices|
|DeviceNetworkEvents|Network connection and related events|
|DeviceNetworkInfo|Network properties of devices, including physical adapters, IP and MAC addresses, as well as connected networks and domains|
|DeviceProcessEvents|Process creation and related events|
|DeviceRegistryEvents|Creation and modification of registry entries|
|DeviceTvmSecureConfigurationAssessment|Microsoft Defender Vulnerability Management assessment events, indicating the status of various security configurations on devices|
|DeviceTvmSecureConfigurationAssessmentKB|Knowledge base of various security configurations used by Microsoft Defender Vulnerability Management to assess devices; includes mappings to various standards and benchmarks|
|DeviceTvmSoftwareInventory|Inventory of software installed on devices, including their version information and end-of-support status|
|DeviceTvmSoftwareVulnerabilities|Software vulnerabilities found on devices and the list of available security updates that address each vulnerability|
|DeviceTvmSoftwareVulnerabilitiesKB|Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available|
|EmailAttachmentInfo|Information about files attached to emails|
|EmailEvents|Microsoft 365 email events, including email delivery and blocking events|
|EmailPostDeliveryEvents|Security events that occur post-delivery, after Microsoft 365 has delivered the emails to the recipient mailbox|
|EmailUrlInfo|Information about URLs on emails|
|IdentityDirectoryEvents|Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller.|
|IdentityInfo|Account information from various sources, including Azure Active Directory|
|IdentityLogonEvents|Authentication events on Active Directory and Microsoft online services|
|IdentityQueryEvents|Queries for Active Directory objects, such as users, groups, devices, and domains|


https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide