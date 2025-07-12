package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.common.Enums;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;

@Data
@Entity
@Table(name = "installment_tbl")
public class Installment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "advance_payment_id")
    private AdvancePayment advancePayment;
    private Double amount;
    private LocalDate dueDate;
    private Enums.InstallmentStatus status;         //PENDING, PAID, OVERDUE
}