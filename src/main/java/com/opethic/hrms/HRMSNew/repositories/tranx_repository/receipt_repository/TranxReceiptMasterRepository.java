package com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository;

import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface TranxReceiptMasterRepository extends JpaRepository<TranxReceiptMaster,Long> {

    @Query(value = " SELECT COUNT(*) FROM tranx_receipt_master_tbl WHERE company_id=?1 And branch_id IS NULL", nativeQuery = true)
    Long findLastRecord(Long id);

    TranxReceiptMaster findByIdAndCompanyIdAndStatus(Long receiptId, Long id, boolean b);

    TranxReceiptMaster findByIdAndStatus(long receiptId, boolean b);

    List<TranxReceiptMaster> findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(Long id, boolean b);

    @Query(value = " SELECT COUNT(*) FROM tranx_receipt_master_tbl WHERE company_id=?1 AND branch_id=?2", nativeQuery = true)
    Long findBranchLastRecord(Long id, Long id1);

    List<TranxReceiptMaster> findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(Long id, Long id1, boolean b);
}
