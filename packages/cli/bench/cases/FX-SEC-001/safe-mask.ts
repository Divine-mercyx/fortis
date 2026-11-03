export const isLiveKey = (k: string) => k.startsWith('sk_live_');
export const describe = (k: string) => `${k.slice(0, 8)}••••`;
