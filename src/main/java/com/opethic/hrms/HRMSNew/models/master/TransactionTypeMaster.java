package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionDetails;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "transaction_type_master_tbl")
public class TransactionTypeMaster {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String transactionName;
    private String transactionCode;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerTransactionDetails> ledgerTransactionDetails;

//    @JsonBackReference
//    @OneToMany(fetch = FetchType.LAZY,
//            cascade = CascadeType.ALL)
//    private List<ProductBarcode> productBarcodes;
//
//    @JsonBackReference
//    @OneToMany(fetch = FetchType.LAZY,
//            cascade = CascadeType.ALL)
//    private List<ProductBatchNo> productBatchNos;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<LedgerTransactionPostings> ledgerTransactionPostings;

//    @JsonBackReference
//    @OneToMany(fetch = FetchType.LAZY,
//            cascade = CascadeType.ALL)
//    private List<InventoryDetailsPostings> inventoryDetailsPostings;


}
