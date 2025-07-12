package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

@Data
@Entity
@Table(name = "attendance_tbl")
public class Attendance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "shift_id", nullable = false)
    private Shift shift;
    private String punchInImage;
    private String punchOutImage;
    private LocalDate attendanceDate;
    private LocalDateTime checkInTime;
    private LocalDateTime checkOutTime;
    private LocalTime totalTime;
    private Double hoursWorked;
    private Double lunchTime;
    private Double wagesPerDay;
    private Double wagesPerHour;
    private Double actualWorkTime; // in minutes (total task time - break time)
    private Double wagesHourBasis;  // sum of wages_hour_basis
    private String salaryType;
    private String attendanceStatus; // approved, pending
    private int overtime;
    private double overtimeAmount;
    private Boolean isHalfDay;
    private Boolean isLate;
    private Boolean isManualPunchIn;
    private Boolean isManualPunchOut;
    private Boolean isPunchInApproved;
    private Boolean isPunchOutApproved;
    private  Boolean isAttendanceApproved;
    private String remark;
    private String adminRemark;
    private Boolean status;
    private LocalDateTime createdAt;
    private Long createdBy;
    private LocalDateTime updatedAt;
    private Long updatedBy;
}
