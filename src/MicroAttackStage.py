from enum import Enum


class MicroAttackStage(Enum):
    """
    Classification for the Micro attack stages defined in
    "Cyberattack Action-Intent-Framework for Mapping Intrusion Observables"
    See https://arxiv.org/pdf/2002.07838.pdf
    """
    INIT = 0

    TARGET_IDEN = 1
    SURFING = 2
    SOCIAL_ENGINEERING = 3
    HOST_DISC = 4
    SERVICE_DISC = 5
    VULN_DISC = 6
    INFO_DISC = 7

    USER_PRIV_ESC = 10
    ROOT_PRIV_ESC = 11
    NETWORK_SNIFFING = 12
    BRUTE_FORCE_CREDS = 13
    ACCT_MANIP = 14
    TRUSTED_ORG_EXP = 15
    PUBLIC_APP_EXP = 16
    REMOTE_SERVICE_EXP = 17
    SPEARPHISHING = 18
    SERVICE_SPECIFIC = 19
    DEFENSE_EVASION = 20
    COMMAND_AND_CONTROL = 21
    LATERAL_MOVEMENT = 22
    ARBITRARY_CODE_EXE = 23
    PRIV_ESC = 99

    END_POINT_DOS = 100
    NETWORK_DOS = 101
    SERVICE_STOP = 102
    RESOURCE_HIJACKING = 103
    DATA_DESTRUCTION = 104
    CONTENT_WIPE = 105
    DATA_ENCRYPTION = 106
    DEFACEMENT = 107
    DATA_MANIPULATION = 108
    DATA_EXFILTRATION = 109
    DATA_DELIVERY = 110
    PHISHING = 111

    NON_MALICIOUS = 999
