import { Optional } from "@nestjs/common";
import { ArrayMinSize, IsArray, IsString } from "class-validator";

export class CreateAdminDto{
    @IsString()
    personId: string;

    @Optional()
    @IsArray()
    @ArrayMinSize(1)
    permissions: string[]
}