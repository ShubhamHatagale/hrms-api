package com.opethic.hrms.HRMSNew.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class ResourceNotFoundException extends RuntimeException{
    String resourceName;
    String fieldName;
    Long fieldValue;

    public ResourceNotFoundException(String resourceName, String fieldName, Long fieldValue){
        super(String.format("%s not found with %s : %s", resourceName, fieldName, fieldValue));
        this.resourceName=resourceName;
        this.fieldName=fieldName;
        this.fieldValue=fieldValue;
    }

}
