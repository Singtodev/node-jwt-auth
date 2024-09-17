export interface User {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface DbUser {
  id: number;
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  role: number;
}
