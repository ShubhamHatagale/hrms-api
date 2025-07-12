package com.opethic.hrms.HRMSNew.repositories.tranx_repository.payment_repository;

import com.opethic.hrms.HRMSNew.models.tranx.payment.TranxPaymentMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;


public interface TranxPaymentMasterRepository extends JpaRepository<TranxPaymentMaster,Long>{
    @Query(
            value = " SELECT COUNT(*) FROM tranx_payment_master_tbl WHERE company_id=?1 AND branch_id IS NULL", nativeQuery = true
    )
    Long findLastRecord(Long id);

    List<TranxPaymentMaster> findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(Long id, Long id1, boolean b);

    TranxPaymentMaster findByIdAndCompanyIdAndStatus(Long paymentId, Long id, boolean b);

    TranxPaymentMaster findByIdAndStatus(long payment_id, boolean b);

    List<TranxPaymentMaster> findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(Long id, boolean b);

    @Query(
            value = " SELECT COUNT(*) FROM tranx_payment_master_tbl WHERE company_id=?1 AND branch_id=?2", nativeQuery = true
    )
    Long findBranchLastRecord(Long id, Long id1);
}
