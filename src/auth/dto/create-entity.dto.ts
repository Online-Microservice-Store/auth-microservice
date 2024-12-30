import { IsString, IsEmail, IsStrongPassword } from "class-validator";

export class CreateEntity{
    //Person atributes
    @IsString()
    name: string;

    @IsString()
    lastname: string;

    @IsString()
    identification: string;
    
    //Profile attributes
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