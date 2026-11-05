declare global {
  namespace App {
    interface Locals {
      actor: "Admin" | null;
      // The address and browser recorded with each change this request makes.
      client: { address: string; agent: string };
      requestId: string;
    }

    interface Error {
      status: number;
      message: string;
      requestId?: string;
    }
  }
}

export {};
