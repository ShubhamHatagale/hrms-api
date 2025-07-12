package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "employee_document_tbl")
public class EmployeeDocument {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonIgnoreProperties(value = {"employee_document", "hibernateLazyInitializer"})
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;
    private String imagePath;
    private String imageKey;
    private Long createdBy;
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
