package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

@Data
public class PayheadDTO {
    private Long id;

    private String name;
    private Double percentage;
    private Double amount;
    private String payheadSlug;
    private String percentageOf;
    private Boolean isdeduction;
    private Boolean showInEmpCreation;
    private String underPrefix;
    private Boolean status;
    private Long createdBy;
    private String createdAt;
    private Long updatedBy;
    private String updatedAt;
}
