/**
 * @swagger
 * components:
 *   schemas:
 *     RegisterDto:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: User's email
 *         password:
 *           type: string
 *           format: password
 *           description: User's password
 */
import { IsBoolean, IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsString()
  identifier!: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsBoolean()
  isEmail!: boolean;
}
