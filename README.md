# AVS-and-PVD-Methodologies

AVS and PVD Results Analysis Methodologies diagrams are two novel vulnerability identification approaches to determine CVEs true positives, false positives and false negatives.

The PVD_method.sh is a tool that conduct Passive Vulnerability Detection (PVD) from local CVE repository. The local CVE repository was generated in sqlite format from NVD (National Vulnerabilities Database) feeds by using a open source tool [1].


Usage:

 If conduct PVD Result Analysis;
    
    Usage	: $0 <CPE List File Path> <Software Version> <AS_TP Result Path>
    Example	: $0 ./software_cpe_list 1.1.2 ./AS_TP_Result

    If only search CVEs from local copy of NVD then use;

    Example	: $0 ./software_cpe_list 1.1.2"
    
[1] https://github.com/vulsio/go-cve-dictionary.git
