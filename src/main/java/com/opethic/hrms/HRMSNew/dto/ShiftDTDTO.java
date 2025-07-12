package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;

@Data
public class ShiftDTDTO {
    private Long id;
    private String shiftName;
    private String startTime;
    private String endTime;
    private String lunchStartTime;
    private String lunchEndTime;
    private String lunchTime;
    private String workingHours;
    private String graceInPeriod;
    private String graceOutPeriod;
    private String secondHalfPunchInTime;
    private String totalHours;
    private Boolean isNightShift;
    private Long considerationCount;   //Late Count to be Considered for deduction
    private Boolean isDayDeduction;
    private String dayValueOfDeduction;
    private double hourValueOfDeduction;
    private Long createdBy;
    private String createdAt;
    private Long updatedBy;
    private String updatedAt;
    private Boolean status;
}
