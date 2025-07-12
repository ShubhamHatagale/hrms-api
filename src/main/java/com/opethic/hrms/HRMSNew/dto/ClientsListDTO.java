package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/* for get sundry creditors, sundry debtors,cash account and  bank accounts for sale */
@Data
public class ClientsListDTO {
    private String message;
    private int responseStatus;
    private List<ClientDetails> list = new ArrayList<>();
}
