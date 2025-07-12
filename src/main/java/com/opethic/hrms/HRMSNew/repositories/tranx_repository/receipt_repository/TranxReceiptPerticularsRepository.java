package com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository;

import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptPerticulars;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface TranxReceiptPerticularsRepository extends JpaRepository<TranxReceiptPerticulars, Long> {
    @Query(value = "SELECT * FROM tranx_receipt_perticulars_tbl WHERE tranx_receipt_master_id=?1 AND company_id=?2 AND status=?3",
            nativeQuery = true)
    List<TranxReceiptPerticulars> findLedgerName(Long id, Long companyId, boolean status);

    List<TranxReceiptPerticulars> findByTranxReceiptMasterIdAndStatus(Long id, boolean b);

    TranxReceiptPerticulars findByIdAndStatus(Long detailsId, boolean b);

    TranxReceiptPerticulars findByStatusAndTranxReceiptMasterId(boolean b, Long id);

    TranxReceiptPerticulars findByIdAndCompanyIdAndBranchIdAndStatus(Long transactionId, Long id, Long id1, boolean b);

    TranxReceiptPerticulars findByIdAndCompanyIdAndStatus(Long transactionId, Long id, boolean b);

    TranxReceiptPerticulars findByTranxReceiptMasterIdAndCompanyIdAndBranchIdAndStatusAndType(Long transactionId, Long id, Long id1, boolean b, String cr);

    TranxReceiptPerticulars findByTranxReceiptMasterIdAndCompanyIdAndStatusAndType(Long transactionId, Long id, boolean b, String cr);
}
