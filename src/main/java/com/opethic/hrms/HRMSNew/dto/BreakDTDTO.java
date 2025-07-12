package com.opethic.hrms.HRMSNew.dto;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Data
public class BreakDTDTO {
    private Long id;
    private String breakName;
    private String fromTime;
    private String toTime;
    private Boolean isBreakPaid;
    private Boolean status;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
}
