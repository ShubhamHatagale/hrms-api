package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "employee_payhead_tbl")
public class EmployeePayhead {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    @JsonIgnoreProperties(value = {"employee_payhead", "hibernateLazyInitializer"})
    @JoinColumn(name = "payhead_id", nullable = false)
    private Payhead payhead;
    private Long createdBy;
    private Double amount;
    private Boolean isDeduction;
    private String underPrefix;
    private Boolean showInEmpCreation;

//    @ManyToOne
//    @JsonManagedReference
//    @JoinColumn(name = "employee_id")
//    private Employee employee;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;
}
