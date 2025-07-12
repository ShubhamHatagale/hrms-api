package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Data
@Entity
@Table(name = "shift_tbl")
public class Shift {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String shiftName;
    private LocalTime startTime;
    private LocalTime endTime;
    private Long lunchTime;
//    private LocalTime lunchStartTime;
//    private LocalTime lunchEndTime;
    private LocalTime workingHours;
    private LocalTime graceInPeriod;
    private LocalTime graceOutPeriod;
    private LocalTime secondHalfPunchInTime;
    private LocalTime totalHours;
    private Boolean isNightShift;
    private Boolean status;
    private Long considerationCount;   //Late Count to be Considered for deduction
    private Boolean isDayDeduction;
    private String dayValueOfDeduction;
    private double hourValueOfDeduction;
    @Column(updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
    @Column(insertable = false)
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Long updatedBy;
    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;
}
