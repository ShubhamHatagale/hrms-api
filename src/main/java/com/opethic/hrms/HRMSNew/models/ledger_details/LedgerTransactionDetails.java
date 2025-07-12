package com.opethic.hrms.HRMSNew.models.ledger_details;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ledger_transaction_details_tbl")
public class LedgerTransactionDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
   /* @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<PaymentTransactionDetails> paymentTransactionDetails;*/

    @ManyToOne
    @JoinColumn(name = "foundation_id")
    @JsonManagedReference
    private Foundations foundations;

    @ManyToOne
    @JoinColumn(name = "principle_id")
    @JsonManagedReference
    private Principles principles;

    @ManyToOne
    @JoinColumn(name = "principle_groups_id")
    @JsonManagedReference
    private PrincipleGroups principleGroups;

    @ManyToOne
    @JoinColumn(name = "ledger_master_id")
    @JsonManagedReference
    private LedgerMaster ledgerMaster;

    @ManyToOne
    @JoinColumn(name = "transaction_type_id")
    @JsonManagedReference
    private TransactionTypeMaster transactionType;

    @ManyToOne
    @JoinColumn(name = "balancing_method_id")
    @JsonManagedReference
    private BalancingMethod balanceMethod;

    @ManyToOne
    @JoinColumn(name = "associate_groups_id")
    @JsonManagedReference
    private AssociateGroups associateGroups;

   /* @ManyToOne(fetch = FetchType.LAZY,
            cascade = {CascadeType.MERGE})
    @JsonIgnoreProperties(value = {"ledger_transaction_details", "hibernateLazyInitializer"})
    @JoinColumn(name = "payment_status_id")
    private PaymentStatus paymentStatus;*/

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    private String paymentStatus;
    private Double debit;
    private Double credit;
    private Double openingBal;
    private Double closingBal;
    private LocalDate transactionDate;
    private LocalDate paymentDate;
    private Long transactionId; // Transaction Id (purchase,sale)
    private String tranxType;
    private String financialYear;
    private String underPrefix;
    private String invoiceNo;

    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
    private Long updatedBy;
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Boolean status;
}
