import type { RulePack } from '@fortis/shared';

import { FINTECH_RULES } from './fintech';
import { CSHARP_FINTECH_RULES } from './fintech-csharp';
import { GO_FINTECH_RULES } from './fintech-go';
import { PYTHON_FINTECH_RULES } from './fintech-python';
import { genericSecretRule, paymentKeyRule } from './secrets';
import type { FileRule } from './types';

export const FILE_RULES: FileRule[] = [paymentKeyRule, genericSecretRule, ...FINTECH_RULES, ...PYTHON_FINTECH_RULES, ...GO_FINTECH_RULES, ...CSHARP_FINTECH_RULES];

export const rulesFor = (packs: readonly RulePack[]) => FILE_RULES.filter((r) => packs.includes(r.pack));
