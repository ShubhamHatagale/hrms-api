package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

@Data
public class ReciptMasterDTDTO {
    private Long id;
    private String receiptNo;
    private double receiptSrNo;
    private String tranxReceiptPerticulars;
    private String transcationDate;
    private double totalAmt;
    private boolean status;
    private String narrations;
    private String financialYear;
    private String createdAt;
    private Long createdBy;
}
