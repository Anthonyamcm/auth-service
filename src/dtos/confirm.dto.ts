import { IsEmail, IsString, isString } from 'class-validator';

export class ConfirmDto {
  @IsString()
  identifier!: string;

  @IsString()
  code!: string;

  @IsString()
  password!: string;
}
