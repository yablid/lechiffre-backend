import { Injectable, BadRequestException } from '@nestjs/common';
import { CreateRoleDto } from './dto/create-role.dto';
import { Role } from './roles.model';
import { DatabaseService } from '../../database/database.service';

@Injectable()
export class RolesService {
  constructor(private readonly databaseService: DatabaseService) {}

  async create(createRoleDto: CreateRoleDto): Promise<Role> {
    const { role_id, name } = createRoleDto;

    const existingRole = await this.databaseService.query(
      'SELECT role_id FROM roles WHERE role_id = $1',
      [role_id]
    );

    if (existingRole.rowCount > 0) {
      throw new BadRequestException(`Role with id ${role_id} already exists`);
    }

    // Insert the new role with the specified role_id
    const result = await this.databaseService.query(
      'INSERT INTO roles (role_id, name) VALUES ($1, $2) RETURNING role_id, name',
      [role_id, name]
    );

    const newRole = result.rows[0];
    return new Role(newRole.role_id, newRole.name);
  }

  async findAll(): Promise<Role[]> {
    // Retrieve all roles from the database
    const result = await this.databaseService.query('SELECT role_id, name FROM roles');

    return result.rows.map(row => new Role(row.role_id, row.name));
  }

  async findById(id: number): Promise<Role> {
    // Retrieve a specific role by its role_id
    const result = await this.databaseService.query(
      'SELECT role_id, name FROM roles WHERE role_id = $1',
      [id]
    );

    if (result.rowCount === 0) {
      throw new BadRequestException(`Role with id ${id} not found`);
    }

    const role = result.rows[0];
    return new Role(role.role_id, role.name);
  }

  // Add other necessary methods as needed
}
