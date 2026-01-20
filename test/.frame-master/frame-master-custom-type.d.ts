// Module declarations for CSS imports
declare module "*.css" {
  const content: string;
  export default content;
}

declare module "openauth-react/types" {
  interface SessionData {
    id: string;
  }
}

export {};
