export interface RecentAccount {
  id: string;
  email: string;
  lastUsedAt: number;
  provider: 'google' | 'telegram' | 'passkey' | 'unknown';
}

const STORAGE_KEY = 'ar_auth_recent_accounts';

export const getRecentAccounts = (): RecentAccount[] => {
  const data = localStorage.getItem(STORAGE_KEY);
  if (!data) return [];
  try {
    const list = JSON.parse(data);
    if (!Array.isArray(list)) return [];
    return list.sort((a, b) => b.lastUsedAt - a.lastUsedAt);
  } catch {
    return [];
  }
};

export const saveRecentAccount = (account: Omit<RecentAccount, 'lastUsedAt'>) => {
  const current = getRecentAccounts();
  const existingIndex = current.findIndex(a => a.email === account.email);
  
  const updated = [...current];
  if (existingIndex > -1) {
    updated[existingIndex] = { ...account, lastUsedAt: Date.now() };
  } else {
    updated.push({ ...account, lastUsedAt: Date.now() });
  }
  
  // Keep only last 5 accounts
  const final = updated.sort((a, b) => b.lastUsedAt - a.lastUsedAt).slice(0, 5);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(final));
};

export const removeRecentAccount = (email: string) => {
  const current = getRecentAccounts();
  const filtered = current.filter(a => a.email !== email);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
};
