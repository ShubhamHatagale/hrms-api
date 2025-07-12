package com.opethic.hrms.HRMSNew.repositories.tranx_repository.receipt_repository;


import com.opethic.hrms.HRMSNew.models.tranx.receipt.TranxReceiptPerticularsDetails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TranxReceiptPerticularsDetailsRepository extends JpaRepository<TranxReceiptPerticularsDetails,Long> {
   List<TranxReceiptPerticularsDetails> findByIdAndStatus(Long id, boolean b);

    TranxReceiptPerticularsDetails findByIdAndCompanyIdAndBranchIdAndStatus(Long tranx_type, Long id, Long id1, boolean b);

    TranxReceiptPerticularsDetails findByIdAndCompanyIdAndStatus(Long tranx_type, Long id, boolean b);
}
