import { IsString } from "class-validator";

export class CreatePersonDto{
    @IsString()
    name: string;

    @IsString()
    lastname: string;

    @IsString()
    identification: string;
}