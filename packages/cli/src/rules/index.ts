import type { RulePack } from '@fortis/shared';

import { FINTECH_RULES } from './fintech';
import { CSHARP_FINTECH_RULES } from './fintech-csharp';
import { GO_FINTECH_RULES } from './fintech-go';
import { JVM_FINTECH_RULES } from './fintech-jvm';
import { MONEY_RULES } from './fintech-money';
import { PHP_FINTECH_RULES } from './fintech-php';
import { genericSecretRule, paymentKeyRule } from './secrets';
import { SUPPLY_CHAIN_RULES } from './supply-chain';
import type { FileRule } from './types';

export const FILE_RULES: FileRule[] = [paymentKeyRule, genericSecretRule, ...FINTECH_RULES, ...GO_FINTECH_RULES, ...CSHARP_FINTECH_RULES, ...PHP_FINTECH_RULES, ...JVM_FINTECH_RULES, ...MONEY_RULES, ...SUPPLY_CHAIN_RULES];

export const rulesFor = (packs: readonly RulePack[]) => FILE_RULES.filter((r) => packs.includes(r.pack));
