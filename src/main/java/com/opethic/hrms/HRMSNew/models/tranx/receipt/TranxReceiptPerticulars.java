package com.opethic.hrms.HRMSNew.models.tranx.receipt;

import com.fasterxml.jackson.annotation.JsonBackReference;
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
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
    @Table(name = "tranx_receipt_perticulars_tbl")
public class TranxReceiptPerticulars {
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

    @ManyToOne
    @JoinColumn(name = "tranx_receipt_master_id")
    @JsonManagedReference
    private TranxReceiptMaster tranxReceiptMaster;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<TranxReceiptPerticularsDetails> tranxReceiptPerticularsDetails;

    private String type;
    private String ledgerType;
    private String ledgerName;
    private double dr;
    private double cr;
    private String paymentMethod;
    private String paymentTranxNo;
    private LocalDate transactionDate;
    private boolean status;
    private Double paymentAmount;
    private Long tranxInvoiceId;
    private String tranxtype;
    private String tranxNo;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
}
