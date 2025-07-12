package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "employee_leave_tbl")
public class EmployeeLeave {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonIgnoreProperties(value = {"employee_leave", "hibernateLazyInitializer"})
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

    @ManyToOne
    @JsonIgnoreProperties(value = {"employee_leave", "hibernateLazyInitializer"})
    @JoinColumn(name = "leave_master_id", nullable = false)
    private LeaveMaster leaveMaster;
    private LocalDate fromDate;
    private LocalDate toDate;
    private LocalDate appliedOn;
    private Integer totalDays;
    private String reason;
    private String leaveStatus;
    private String leaveApprovedBy;
    private String leaveRemark;
    private Boolean status;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
}
