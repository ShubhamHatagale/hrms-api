package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class ContraMasterDTDTO {
    private Long id;
    private String contraNo;
    private double contraSrNo;
    private LocalDate transcationDate;
    private double totalAmt;
    private boolean status;
    private String narrations;
    private String financialYear;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
}
