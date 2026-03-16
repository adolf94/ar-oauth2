export {};

declare global {
  interface Window {
    webConfig?: {
      loginWithEmail?: boolean;
    };
  }
}
