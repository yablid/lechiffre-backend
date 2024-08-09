// src/models/auth/roles.model.ts

export class Role {
  role_id: number;
  name: string;

  constructor(roleId: number, name: string) {
    this.role_id = roleId;
    this.name = name;
  }
}

export default Role