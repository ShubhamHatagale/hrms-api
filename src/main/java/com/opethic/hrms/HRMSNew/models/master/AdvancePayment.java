package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.opethic.hrms.HRMSNew.common.Enums;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "advance_payment_tbl")
public class AdvancePayment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    @JsonIgnoreProperties(value = {"advance_payment", "hibernateLazyInitializer"})
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;
    private Integer requestAmount;
    private String reason;
    private LocalDate dateOfRequest;
    private String approvedBy;
    private String remark;
    private Enums.PaymentStatus paymentStatus; // PENDING, APPROVED, REJECTED
    private LocalDate paymentDate;
    private Double paidAmount;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;
    private Boolean isInstallment;
    private Double installmentAmount;
    private Integer noOfInstallments;
}
