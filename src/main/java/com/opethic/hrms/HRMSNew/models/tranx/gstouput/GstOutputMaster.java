package com.opethic.hrms.HRMSNew.models.tranx.gstouput;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Company;
import com.opethic.hrms.HRMSNew.models.master.FiscalYear;
import com.opethic.hrms.HRMSNew.models.master.LedgerMaster;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tranx_gst_output_tbl")
public class GstOutputMaster {
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
    @JoinColumn(name = "debtor_id")
    @JsonManagedReference
    private LedgerMaster debtorsLedger;

    @ManyToOne
    @JoinColumn(name = "posting_ledger_id")
    @JsonManagedReference
    private LedgerMaster postingLedger;

    @ManyToOne
    @JoinColumn(name = "fiscal_year_id")
    @JsonManagedReference
    private FiscalYear fiscalYear;

//    @ManyToOne
//    @JoinColumn(name = "payment_mode_id")
//    @JsonManagedReference
//    private PaymentModeMaster paymentModeMaster;

    @ManyToOne
    @JoinColumn(name = "roundoff_id")
    @JsonManagedReference
    private LedgerMaster roundOffLedger;

    private Double roundOff;
    private Double totalIgst;
    private Double totalCgst;
    private Double totalSgst;
    private String voucherSrNo;
    private String voucherNo;
    private LocalDate tranxDate;
    private LocalDate voucherDate;
    private String narrations;
    private String paymentTranxNo;
    private Double totalAmount;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
    private Boolean status;
    private Long updatedBy;
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstOutputDetails> gstOutputDetails;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstOutputDutiesTaxes> gstOutputDutiesTaxes;

}
