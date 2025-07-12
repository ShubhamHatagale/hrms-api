package com.opethic.hrms.HRMSNew.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseMessage {
    private String message = null;
    private int responseStatus;
    private Object responseObject;
    private Object response;
    private String data;

}
