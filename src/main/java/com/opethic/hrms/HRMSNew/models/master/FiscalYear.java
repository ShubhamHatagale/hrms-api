package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.tranx.contra.TranxContraMaster;
import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputMaster;
import com.opethic.hrms.HRMSNew.models.tranx.gstouput.GstOutputMaster;
import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalMaster;
import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentMaster;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "fiscal_year_tbl")
public class FiscalYear {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private int monthStart;
    private int monthEnd;
    private LocalDate dateStart;
    private LocalDate dateEnd;
    private String fiscalYear;
    private LocalDate fiscalYearEndDate;
    private String abbreviation;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Boolean status;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerTransactionPostings> ledgerTransactionPostings;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<TranxContraMaster> tranxContraMasters;

//    @JsonBackReference
//    @OneToMany(fetch = FetchType.LAZY,
//            cascade = CascadeType.ALL)
//    private List<TranxReceiptMaster> tranxReceiptMasters;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<TranxPaymentMaster> tranxPaymentMasters;


    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<TranxJournalMaster> tranxJournalMasters;

//    @JsonBackReference
//    @OneToMany(fetch = FetchType.LAZY,
//            cascade = CascadeType.ALL)
//    private List<InventoryDetailsPostings> inventoryDetailsPostings;


    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstInputMaster> gstInputMasters;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstOutputMaster> gstOutputMasters;

}
