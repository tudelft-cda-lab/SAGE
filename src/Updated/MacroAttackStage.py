from enum import Enum


class MacroAttackStage(Enum):
    """
    Classification for the Macro attack stages defined in
    "Cyberattack Action-Intent-Framework for Mapping Intrusion Observables"
    See https://arxiv.org/pdf/2002.07838.pdf
    """
    NONE = 0
    PASSIVE_RECON = 1
    ACTIVE_RECON = 2
    PRIVLEDGE_ESC = 3
    ENSURE_ACCESS = 4
    TARGETED_EXP = 5
    ZERO_DAY = 6
    DISRUPT = 7
    DISTROY = 8
    DISTORT = 9
    DISCLOSURE = 10
    DELIVERY = 11


macro = {0: 'MacroAttackStage.NONE',
         1: 'MacroAttackStage.PASSIVE_RECON',
         2: 'MacroAttackStage.ACTIVE_RECON',
         3: 'MacroAttackStage.PRIVLEDGE_ESC',
         4: 'MacroAttackStage.ENSURE_ACCESS',
         5: 'MacroAttackStage.TARGETED_EXP',
         6: 'MacroAttackStage.ZERO_DAY',
         7: 'MacroAttackStage.DISRUPT',
         8: 'MacroAttackStage.DISTROY',
         9: 'MacroAttackStage.DISTORT',
         10: 'MacroAttackStage.DISCLOSURE',
         11: 'MacroAttackStage.DELIVERY',
         }
