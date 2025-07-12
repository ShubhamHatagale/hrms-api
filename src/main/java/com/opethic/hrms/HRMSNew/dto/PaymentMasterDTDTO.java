package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

@Data
public class PaymentMasterDTDTO {
    private Long id;
    private String paymentNo;
    private double paymentSrNo;
    private String transcationDate;
    private double totalAmt;
    private boolean status;
    private String narrations;
    private String financialYear;
    private String createdAt;
    private Long createdBy;
}
