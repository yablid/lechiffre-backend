// src/modules/users/users.model.ts
import Role from '../roles/roles.model';

class User {
  id?: string;
  username: string;
  password: string;
  roles: Role[];
  date_created: Date;

  constructor(username: string, password: string, roles: Role[], id?: string) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.roles = roles;
    this.date_created = new Date();
  }
}

export default User;
