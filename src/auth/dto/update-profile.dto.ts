import { PartialType } from "@nestjs/mapped-types";
import { CreatePersonDto } from "./create-person.dto";
import { IsString } from "class-validator";

export class UpdateProfileDto extends PartialType(CreatePersonDto){
    @IsString()
    id : string;
}