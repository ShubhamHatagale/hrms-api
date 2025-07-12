package com.opethic.hrms.HRMSNew.models.tranx.gstinput;

import com.fasterxml.jackson.annotation.JsonBackReference;
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
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tranx_gst_input_tbl")
public class GstInputMaster {
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
    @JoinColumn(name = "supplier_id")
    @JsonManagedReference
    private LedgerMaster supplierLedger;

    @ManyToOne
    @JoinColumn(name = "posting_ledger_id")
    @JsonManagedReference
    private LedgerMaster postingLedger;

    @ManyToOne
    @JoinColumn(name = "fiscal_year_id")
    @JsonManagedReference
    private FiscalYear fiscalYear;

    @ManyToOne
    @JoinColumn(name = "payment_mode_id")
    @JsonManagedReference
    private PaymentModeMaster paymentModeMaster;

    @ManyToOne
    @JoinColumn(name = "roundoff_id")
    @JsonManagedReference
    private LedgerMaster roundOffLedger;

    private Double totalIgst;
    private Double roundOff;
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
    private List<GstInputDetails> gstInputDetails;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstInputDutiesTaxes> gstInputDutiesTaxes;

}
