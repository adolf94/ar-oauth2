export {};

declare global {
  interface Window {
    webConfig?: {
      authUri?: string;
    };
  }
}
