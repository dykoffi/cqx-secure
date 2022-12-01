export function verify(): boolean;
export function crypt(data: any, algorithm: any, key: any, iv: any): string;
export function dcrypt(data: any, algorithm: any, key: any, iv: any): string;
export function logError(...message: any[]): void;
export function logSuccess(...message: any[]): void;
export function logInfo(...message: any[]): void;
export const algo: "aes-256-gcm";
