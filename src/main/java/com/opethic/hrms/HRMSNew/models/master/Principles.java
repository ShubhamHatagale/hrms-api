package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerBalanceSummary;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "principles_tbl")
public class Principles {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String principleName;
    private String uniqueCode;

    @ManyToOne
    @JoinColumn(name = "foundation_id")
    @JsonManagedReference
    private Foundations foundations;

    @ManyToOne
    @JoinColumn(name = "ledger_form_parameter_id")
    @JsonManagedReference
    private LedgerFormParameter ledgerFormParameter;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<PrincipleGroups> principleGroups;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerMaster> ledgerMasters;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<AssociateGroups> associateGroups;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerBalanceSummary> ledgerBalanceSummaries;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerTransactionDetails> ledgerTransactionDetails;

    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Boolean status;


}
