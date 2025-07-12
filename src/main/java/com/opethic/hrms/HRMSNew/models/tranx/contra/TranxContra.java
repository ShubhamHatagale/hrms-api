package com.opethic.hrms.HRMSNew.models.tranx.contra;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Company;
import com.opethic.hrms.HRMSNew.models.master.LedgerMaster;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tranx_contra_tbl")
public class TranxContra {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    @ManyToOne
    @JoinColumn(name = "ledger_id")
    @JsonManagedReference
    private LedgerMaster ledgerMaster;


    private String type; //Cr or Dr
    private String ledgerType;
    private Long contraSrNo;
    private LocalDate tranxDate;
    private Double paidAmount;
    private Double balance;
    private String payment_type; //cash ,cheque, UPI id
    private String bankName;
    private String narrations;
    private String contraUniqueNo; //unique number of payment
    private String bankPaymentNo;
    private String financialYear;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
    private Boolean status;
}

