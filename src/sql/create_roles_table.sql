/* src/sql/create_roles_table.sql */
CREATE TABLE IF NOT EXISTS roles (
  role_id INT PRIMARY KEY,  -- Use INT and define it as the primary key
  name VARCHAR(50) NOT NULL
);

INSERT INTO roles (role_id, name)
VALUES
    (10, 'jefe'),
    (20, 'admin'),
    (30, 'supervisor'),
    (40, 'manager'),
    (50, 'engineer'),
    (90, 'guest')
ON CONFLICT (role_id) DO NOTHING;

