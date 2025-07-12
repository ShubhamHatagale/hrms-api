package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "employee_education_tbl")
public class EmployeeEducation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String institutionName;
    private String qualification;
    private String university;
    private String year;
    private String grade;
    private String percentage;
//    @ManyToOne
//    @JsonManagedReference
//    @JoinColumn(name = "employee_id")
//    private Employee employee;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;

}
