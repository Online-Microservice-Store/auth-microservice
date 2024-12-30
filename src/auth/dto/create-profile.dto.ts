import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class CreateProfileDto{
    @IsString()
    username: string;

    @IsString()
    @IsStrongPassword()
    password: string;

    @IsString()
    @IsEmail()
    email: string;

    @IsString()
    ocupation: string;
}