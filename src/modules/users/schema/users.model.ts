// src/modules/users/users.model.ts
import Role from '../../roles/schema/roles.model';

// todo: don't need roles here anymore as there is a join table

class User {
  id?: string;
  email: string;
  password: string;
  role_id: number;
  date_created: Date;

  constructor(email: string, password: string, role_id: number, id?: string) {
    this.id = id;
    this.email = email;
    this.password = password;
    this.role_id = role_id;
    this.date_created = new Date();
  }
}

export default User;
