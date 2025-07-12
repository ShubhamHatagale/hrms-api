package com.opethic.hrms.HRMSNew.models.ledger_details;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ledger_balance_summary_tbl")
public class LedgerBalanceSummary {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
    @JoinColumn(name = "associate_groups_id")
    @JsonManagedReference
    private AssociateGroups associateGroups;

    @ManyToOne
    @JoinColumn(name = "ledger_master_id")
    @JsonManagedReference
    private LedgerMaster ledgerMaster;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    private Double debit;
    private Double credit;
    private Double openingBal;
    private Double closingBal;
    private Double balance;
    private String underPrefix;
    @CreationTimestamp
    private LocalDateTime createdAt;
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Boolean status;
}
