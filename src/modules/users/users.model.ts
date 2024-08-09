// src/models/auth/users.model.ts
import Role from '../roles/roles.model';

class User {
  id: number;
  username: string;
  password: string;
  roles: Role[];
  date_created: Date;

  constructor(id: number, username: string, password: string, roles: Role[]) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.roles = roles;
    this.date_created = new Date();
  }
}

export default User;
