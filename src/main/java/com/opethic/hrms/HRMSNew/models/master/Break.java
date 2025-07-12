package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Data
@Entity
@Table(name = "break_tbl")
public class Break {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;
    @ManyToOne
    @JsonIgnoreProperties(value = {"users", "hibernateLazyInitializer"})
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;
    @ManyToOne
    @JsonIgnoreProperties(value = {"users", "hibernateLazyInitializer"})
    @JoinColumn(name = "attendance_id", nullable = false)
    private Attendance attendance;
    @ManyToOne
    @JsonIgnoreProperties(value = {"users", "hibernateLazyInitializer"})
    @JoinColumn(name = "break_master_id", nullable = false)
    private BreakMaster breakMaster;
    private String remark;
    private String breakStatus;
    private LocalDate breakDate;
    private LocalTime breakStartTime;
    private LocalTime breakEndTime;
    private Double totalBreakTime; // in minutes
    private Long createdBy;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;
}
