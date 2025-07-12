package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

/* for get sundry creditors, sundry debtors,cash account and  bank accounts for sale */
@Data
public class ClientDetails {
    private Long id;
    private String ledger_name;
    private String ledger_code;
    private String stateCode;
}
