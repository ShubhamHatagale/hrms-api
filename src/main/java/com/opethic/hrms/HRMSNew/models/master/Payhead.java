package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Entity
@Table(name = "payhead_tbl")
public class Payhead {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private Double percentage;
    private Double amount;
    private String payheadSlug;
    private Boolean isDefault;
    private Boolean isDeduction;
    private Boolean showInEmpCreation;
    @OneToOne(optional = true)
    @JsonIgnoreProperties(value = {"payhead", "hibernateLazyInitializer"})
    @JoinColumn(name = "percentage_of", nullable = true)
    private Payhead percentageOf;
    private Long createdBy;
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;
    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;
}
